#!/usr/bin/env python3
"""
Enrichment pipeline for threat feeds data.

Reads URLs from threat_feeds_raw.db (OpenPhish + PhishTank **live feed snapshots**
from `grabrawdata`: regularly re-fetch so rows match URLs still listed as active /
online-valid) and enriches them with:
- WHOIS information (domain registration, registrar, dates, nameservers)
- GeoIP data (country, region, city, coordinates)
- ASN/ISP information (network owner, ISP name)
- SSL certificate details (issuer, validity, serial)
- DNS resolution (IP addresses)

Stores enriched data in threat_feeds.db (enriched_threats table).

PERFORMANCE OPTIMIZATIONS:
- Async I/O for network operations (DNS, HTTP, SSL)
- Concurrent processing of multiple URLs
- Thread pool for blocking operations (WHOIS, IPWhois)
- Batch database inserts
- Connection pooling for GeoIP databases
"""

import ssl
import socket
import sqlite3
import sys
import time
import argparse
import asyncio
import warnings
import re
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import logging

# Suppress all warnings from libraries (urllib3, SSL, etc.)
warnings.filterwarnings('ignore')

# Disable ALL logging from noisy libraries (must be done BEFORE imports)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').propagate = False
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('requests').propagate = False
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').propagate = False
logging.getLogger('aiohttp').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp').propagate = False
logging.getLogger('aiohttp.client').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp.client').propagate = False
logging.getLogger('aiohttp.server').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp.server').propagate = False
logging.getLogger('aiohttp.access').setLevel(logging.CRITICAL)
logging.getLogger('aiohttp.access').propagate = False

# Set global socket timeout for DNS operations (performance boost)
socket.setdefaulttimeout(0.5)  # Even more aggressive!

# Repo root (parent of app/) for install hints — enrich lives in app/database/.
# Bundle root (directory that contains fusion_kit/ and requirements.txt).
_ENRICH_REPO_ROOT = Path(__file__).resolve().parents[1]
_REQUIREMENTS_FILE = _ENRICH_REPO_ROOT / "requirements.txt"

# Optional dependencies - graceful degradation if not available
try:
    import whois
    WHOIS_AVAILABLE = True
    # python-whois logs every socket/DNS failure at ERROR — floods the console on bulk enrich.
    for _whois_log in ("whois", "whois.whois"):
        _wl = logging.getLogger(_whois_log)
        _wl.setLevel(logging.CRITICAL)
        _wl.propagate = False
except ImportError:
    WHOIS_AVAILABLE = False
    print("Warning: python-whois not installed. WHOIS lookups disabled.", file=sys.stderr)
    print(
        f"  Fix for this interpreter ({sys.executable}):\n"
        f"    {sys.executable} -m pip install python-whois\n"
        f"  Or from repo root: {sys.executable} -m pip install -r {_REQUIREMENTS_FILE}",
        file=sys.stderr,
    )

try:
    import requests
    REQUESTS_AVAILABLE = True
    try:
        from urllib3.util.retry import Retry
    except ImportError:
        Retry = None  # type: ignore[misc, assignment]
except ImportError:
    REQUESTS_AVAILABLE = False
    Retry = None  # type: ignore[misc, assignment]
    print("Warning: requests not installed. HTTP checks disabled.")
    print("Install with: pip install requests")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    # Not critical - we have requests fallback

# SSRF guard for outbound fetches (sidecar enrichment of user-submitted URLs).
# Mirrors internal/phishing/enricher/http.go safeDialContext.
from fusion_kit.safe_http import (
    SSRFGuardedAdapter,
    SSRFGuardedConnector,
    mount_ssrf_guard,
    safe_create_connection,
)

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    print("Warning: geoip2 not installed. GeoIP lookups disabled.")
    print("Install with: pip install geoip2")

try:
    from langdetect import detect, LangDetectException
    LANGDETECT_AVAILABLE = True
except ImportError:
    LANGDETECT_AVAILABLE = False
    print("Warning: langdetect not installed. Language detection will use heuristics.")
    print("Install with: pip install langdetect")

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False
    print("Warning: ipwhois not installed. ASN / RDAP lookups disabled.", file=sys.stderr)
    print(
        f"  Fix for this interpreter ({sys.executable}):\n"
        f"    {sys.executable} -m pip install ipwhois\n"
        f"  Or from repo root: {sys.executable} -m pip install -r {_REQUIREMENTS_FILE}",
        file=sys.stderr,
    )

# Configure logging (WARNING level for performance - no INFO/DEBUG spam)
logging.basicConfig(
    level=logging.WARNING,
    format='%(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database paths
DB_DIR = Path(__file__).parent
RAW_DB_PATH = DB_DIR / "threat_feeds_raw.db"
ENRICHED_DB_PATH = DB_DIR / "threat_feeds.db"

# Debug logger (will be configured later based on --debug flag)
debug_logger = logging.getLogger('enrichment_debug')
debug_logger.setLevel(logging.CRITICAL)  # Disabled by default
debug_logger.addHandler(logging.NullHandler())  # No output by default

# GeoIP database paths (MaxMind GeoLite2)
GEOIP_CITY_DB = DB_DIR / "GeoLite2-City.mmdb"
GEOIP_ASN_DB = DB_DIR / "GeoLite2-ASN.mmdb"
GEOIP_COUNTRY_DB = DB_DIR / "GeoLite2-Country.mmdb"

# Timeouts: slightly relaxed vs old “ultra aggressive” defaults to improve
# WHOIS/SSL/page fill rates; HTTP session still uses connection pooling + retries.
WHOIS_DELAY = 0.0
DNS_TIMEOUT = 0.5
SSL_TIMEOUT = 2.5
HTTP_TIMEOUT = 2.5  # HEAD / light probes
PAGE_CONTENT_TIMEOUT = 5.0  # GET body for title (slower endpoints)
MAX_RETRIES = 0  # legacy name; HTTP retries configured on Session adapter

_DEFAULT_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

# Concurrency settings (MAXIMUM PARALLELISM)
MAX_CONCURRENT_URLS = 100  # Doubled for max throughput
MAX_WORKER_THREADS = 200  # Doubled for max parallelism
BATCH_INSERT_SIZE = 200  # Doubled for fewer DB operations

# Global caches for performance
_geoip_city_reader = None
_geoip_asn_reader = None
_geoip_country_reader = None
_http_session = None  # Reusable requests session
_dns_cache = {}  # DNS resolution cache for repeated domains

# Pre-compile commonly used regex patterns (HUGE speedup)
_TITLE_REGEX = re.compile(
    r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
_LANG_REGEX = re.compile(
    r'<html[^>]+lang=["\']([^"\']+)["\']', re.IGNORECASE)
_FORM_ACTION_REGEX = re.compile(
    r'<form[^>]+action=["\']([^"\'#?][^"\']*)["\']', re.IGNORECASE)
# DOM content signals
_FAVICON_REGEX = re.compile(
    r'<link[^>]+rel=["\'][^"\']*(?:shortcut\s+)?icon[^"\']*["\'][^>]+href=["\']([^"\']+)["\']'
    r'|<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'][^"\']*(?:shortcut\s+)?icon[^"\']*["\']',
    re.IGNORECASE)
_PASSWORD_FIELD_REGEX = re.compile(
    r'<input[^>]+type\s*=\s*["\']?password["\']?', re.IGNORECASE)
_HIDDEN_REDIRECT_REGEX = re.compile(
    r'<input[^>]+type\s*=\s*["\']?hidden["\']?[^>]+name\s*=\s*["\']?'
    r'(?:redirect|return|return_to|next|goto|url|back|callback|destination)["\']?',
    re.IGNORECASE)

# Well-known URL shortener services whose opaque codes hide the destination
# 1,479 URL shortener domains — source: github.com/PeterDaveHello/url-shorteners
# Fetched 2026-05-15. Covers all major shortening services.
_SHORTENER_APEXES: frozenset[str] = frozenset({
    '0.gp', '02faq.com', '0a.sk', '101.gg',
    '12ne.ws', '17mimei.club', '1drv.ms', '1ea.ir',
    '1kh.de', '1o2.ir', '1shop.io', '1un.fr',
    '1url.cz', '2.gp', '2.ht', '2.ly',
    '2doc.net', '2fear.com', '2kgam.es', '2link.cc',
    '2nu.gs', '2pl.us', '2u.lc', '2u.pw',
    '2wsb.tv', '3.cn', '3.ly', '301.link',
    '3le.ru', '4.gp', '4.ly', '49rs.co',
    '4sq.com', '5.gp', '53eig.ht', '5du.pl',
    '5w.fit', '6.gp', '6.ly', '69run.fun',
    '6g6.eu', '7.ly', '707.su', '71a.xyz',
    '7news.link', '7ny.tv', '7oi.de', '8.ly',
    '89q.sk', '92url.com', '985.so', '98pro.cc',
    '9mp.com', '9splay.store', 'a.189.cn', 'a.co',
    'a360.co', 'aarp.info', 'ab.co', 'abc.li',
    'abc11.tv', 'abc13.co', 'abc7.la', 'abc7.ws',
    'abc7ne.ws', 'abcn.ws', 'abe.ma', 'abelinc.me',
    'abnb.me', 'abr.ai', 'abre.ai', 'accntu.re',
    'accu.ps', 'acer.co', 'acer.link', 'aces.mp',
    'acortar.link', 'act.gp', 'acus.org', 'adaymag.co',
    'adbl.co', 'adfoc.us', 'adm.to', 'adobe.ly',
    'adol.us', 'adweek.it', 'aet.na', 'agrd.io',
    'ai6.net', 'aje.io', 'aka.ms', 'al.st',
    'alexa.design', 'alli.pub', 'alnk.to', 'alpha.camp',
    'alphab.gr', 'alturl.com', 'amays.im', 'amba.to',
    'amc.film', 'amex.co', 'ampr.gs', 'amrep.org',
    'amz.run', 'amzn.com', 'amzn.pw', 'amzn.to',
    'ana.ms', 'anch.co', 'ancstry.me', 'andauth.co',
    'anon.to', 'anyimage.io', 'aol.it', 'aon.io',
    'apne.ws', 'app.philz.us', 'apple.co', 'apple.news',
    'aptg.tw', 'arah.in', 'arc.ht', 'arkinv.st',
    'asics.tv', 'asin.cc', 'asq.kr', 'asus.click',
    'at.vibe.com', 'atm.tk', 'atmilb.com', 'atmlb.com',
    'atres.red', 'autode.sk', 'avlne.ws', 'avlr.co',
    'avydn.co', 'axios.link', 'axoni.us', 'ay.gy',
    'azc.cc', 'b-gat.es', 'b.link', 'b.mw',
    'b23.ru', 'b23.tv', 'b2n.ir', 'baratun.de',
    'bayareane.ws', 'bbc.in', 'bbva.info', 'bc.vc',
    'bca.id', 'bcene.ws', 'bcove.video', 'bcsite.io',
    'bddy.me', 'beats.is', 'benqurl.biz', 'beth.games',
    'bfpne.ws', 'bg4.me', 'bhpho.to', 'bigcc.cc',
    'bigfi.sh', 'biggo.tw', 'biibly.com', 'binged.it',
    'bit.ly', 'bitly.com', 'bitly.is', 'bitly.lc',
    'bityl.co', 'bl.ink', 'blap.net', 'blbrd.cm',
    'blck.by', 'blizz.ly', 'bloom.bg', 'blstg.news',
    'blur.by', 'bmai.cc', 'bnds.in', 'bnetwhk.com',
    'bo.st', 'boa.la', 'boile.rs', 'bom.so',
    'bonap.it', 'booki.ng', 'bookstw.link', 'bose.life',
    'boston25.com', 'bp.cool', 'br4.in', 'bravo.ly',
    'bridge.dev', 'brief.ly', 'brook.gs', 'browser.to',
    'bst.bz', 'bstk.me', 'btm.li', 'btwrdn.com',
    'budurl.com', 'buff.ly', 'bung.ie', 'bwnews.pr',
    'by2.io', 'bytl.fr', 'bzfd.it', 'bzh.me',
    'c11.kr', 'c87.to', 'cadill.ac', 'can.al',
    'canon.us', 'capital.one', 'capitalfm.co', 'captl1.co',
    'careem.me', 'caro.sl', 'cart.mn', 'casio.link',
    'cathaybk.tw', 'cathaysec.tw', 'cb.com', 'cbj.co',
    'cbsloc.al', 'cbsn.ws', 'cbt.gg', 'cc.cc',
    'cdl.booksy.com', 'centi.ai', 'cfl.re', 'chip.tl',
    'chl.li', 'chn.ge', 'chn.lk', 'chng.it',
    'chts.tw', 'chzb.gr', 'cin.ci', 'cindora.club',
    'circle.ci', 'cirk.me', 'cisn.co', 'citi.asia',
    'cjky.it', 'ckbe.at', 'cl.ly', 'clarobr.co',
    'clc.am', 'clc.to', 'clck.ru', 'cle.clinic',
    'cli.re', 'clickmeter.com', 'clicky.me', 'clr.tax',
    'clvr.rocks', 'cmon.co', 'cmu.is', 'cmy.tw',
    'cna.asia', 'cnb.cx', 'cnet.co', 'cnfl.io',
    'cnn.it', 'cnnmon.ie', 'cnvrge.co', 'cockroa.ch',
    'comca.st', 'come.ac', 'conta.cc', 'cookcenter.info',
    'coop.uk', 'cort.as', 'coupa.ng', 'cplink.co',
    'cr8.lv', 'crackm.ag', 'crdrv.co', 'credicard.biz',
    'crwd.fr', 'crwd.in', 'crwdstr.ke', 'cs.co',
    'csmo.us', 'cstu.io', 'ctbc.tw', 'ctfl.io',
    'cultm.ac', 'cup.org', 'cut.lu', 'cut.pe',
    'cutt.ly', 'cvent.me', 'cvs.co', 'cyb.ec',
    'cybr.rocks', 'd-sh.io', 'da.gd', 'dai.ly',
    'dailym.ai', 'dainik-b.in', 'datayi.cn', 'davidbombal.wiki',
    'db.tt', 'dbricks.co', 'dcps.co', 'dd.ma',
    'deb.li', 'dee.pl', 'deli.bz', 'dell.to',
    'deloi.tt', 'dems.me', 'dhk.gg', 'di.sn',
    'dibb.me', 'dis.gd', 'dis.tl', 'discord.gg',
    'discvr.co', 'disq.us', 'dive.pub', 'dk.rog.gg',
    'dkng.co', 'dky.bz', 'dl.gl', 'dld.bz',
    'dlsh.it', 'dlvr.it', 'dmdi.pl', 'dmreg.co',
    'do.co', 'dockr.ly', 'dopice.sk', 'dpmd.ai',
    'dpo.st', 'dssurl.com', 'dtdg.co', 'dtsx.io',
    'dub.sh', 'dv.gd', 'dvrv.ai', 'dw.com',
    'dwz.tax', 'dxc.to', 'dy.fi', 'dy.si',
    'e.lilly', 'e.vg', 'ebay.to', 'econ.st',
    'ed.gr', 'edin.ac', 'edu.nl', 'eepurl.com',
    'efshop.tw', 'ela.st', 'elle.re', 'ellemag.co',
    'embt.co', 'emirat.es', 'engt.co', 'enshom.link',
    'entm.ag', 'envs.sh', 'epochtim.es', 'ept.ms',
    'eqix.it', 'es.pn', 'es.rog.gg', 'escape.to',
    'esl.gg', 'eslite.me', 'esqr.co', 'esun.co',
    'etoro.tw', 'etp.tw', 'etsy.me', 'everri.ch',
    'exe.io', 'exitl.ag', 'ezstat.ru', 'f1.com',
    'f5yo.com', 'fa.by', 'fal.cn', 'fam.ag',
    'fandan.co', 'fandom.link', 'fandw.me', 'faras.link',
    'faturl.com', 'fav.me', 'fave.co', 'fb.me',
    'fb.watch', 'fbstw.link', 'fce.gg', 'fetnet.tw',
    'fevo.me', 'ff.im', 'fifa.fans', 'firsturl.de',
    'firsturl.net', 'flic.kr', 'flip.it', 'flomuz.io',
    'flq.us', 'fltr.ai', 'flx.to', 'fmurl.cc',
    'fn.gg', 'fnb.lc', 'foodtv.com', 'fooji.info',
    'ford.to', 'forms.gle', 'forr.com', 'found.ee',
    'fox.tv', 'fr.rog.gg', 'frdm.mobi', 'fstrk.cc',
    'ftnt.net', 'fumacrom.com', 'fvrr.co', 'fwme.eu',
    'fxn.ws', 'g-web.in', 'g.asia', 'g.co',
    'g.page', 'ga.co', 'gandi.link', 'garyvee.com',
    'gaw.kr', 'gbod.org', 'gbpg.net', 'gbte.tech',
    'gdurl.com', 'gek.link', 'gen.cat', 'geni.us',
    'genie.co.kr', 'getf.ly', 'geti.in', 'gfuel.ly',
    'gh.io', 'ghkp.us', 'gi.lt', 'gigaz.in',
    'git.io', 'github.co', 'gizmo.do', 'gjk.id',
    'glblctzn.co', 'glblctzn.me', 'gldr.co', 'glmr.co',
    'glo.bo', 'gma.abc', 'gmj.tw', 'go-link.ru',
    'go.aws', 'go.btwrdn.co', 'go.cwtv.com', 'go.dbs.com',
    'go.edh.tw', 'go.gcash.com', 'go.hny.co', 'go.id.me',
    'go.intel-academy.com', 'go.intigriti.com', 'go.jc.fm', 'go.lamotte.fr',
    'go.lu-h.de', 'go.ly', 'go.nasa.gov', 'go.nowth.is',
    'go.osu.edu', 'go.qb.by', 'go.rebel.pl', 'go.shell.com',
    'go.shr.lc', 'go.sony.tw', 'go.tinder.com', 'go.usa.gov',
    'go.ustwo.games', 'go.vic.gov.au', 'godrk.de', 'gofund.me',
    'gomomento.co', 'goo-gl.me', 'goo.by', 'goo.gl',
    'goo.gle', 'goo.su', 'goolink.cc', 'goolnk.com',
    'gosm.link', 'got.cr', 'got.to', 'gov.tw',
    'gowat.ch', 'gph.to', 'gq.mn', 'gr.pn',
    'grb.to', 'grdt.ai', 'grm.my', 'grnh.se',
    'gtly.ink', 'gtly.to', 'gtne.ws', 'gtnr.it',
    'gym.sh', 'haa.su', 'han.gl', 'hashi.co',
    'hbaz.co', 'hbom.ax', 'her.is', 'herff.ly',
    'hf.co', 'hi.kktv.to', 'hi.sat.cool', 'hi.switchy.io',
    'hicider.com', 'hideout.cc', 'hill.cm', 'histori.ca',
    'hmt.ai', 'hnsl.mn', 'homes.jp', 'hp.care',
    'hpe.to', 'hrbl.me', 'href.li', 'ht.ly',
    'htgb.co', 'htl.li', 'htn.to', 'httpslink.com',
    'hubs.la', 'hubs.li', 'hubs.ly', 'huffp.st',
    'hulu.tv', 'huma.na', 'hyperurl.co', 'hyperx.gg',
    'i-d.co', 'i.coscup.org', 'i.mtr.cool', 'ibb.co',
    'ibf.tw', 'ibit.ly', 'ibm.biz', 'ibm.co',
    'ic9.in', 'icit.fr', 'icks.ro', 'iea.li',
    'ifix.gd', 'ift.tt', 'iherb.co', 'ihr.fm',
    'ii1.su', 'iii.im', 'il.rog.gg', 'ilang.in',
    'illin.is', 'iln.io', 'ilnk.io', 'imdb.to',
    'ind.pn', 'indeedhi.re', 'indy.st', 'infy.com',
    'inlnk.ru', 'insig.ht', 'instagr.am', 'intel.ly',
    'interc.pt', 'intuit.me', 'invent.ge', 'inx.lv',
    'ionos.ly', 'ipgrabber.ru', 'ipgraber.ru', 'iplogger.co',
    'iplogger.com', 'iplogger.info', 'iplogger.org', 'iplogger.ru',
    'iplwin.us', 'iqiyi.cn', 'irng.ca', 'is.gd',
    'isw.pub', 'itsh.bo', 'itvty.com', 'ity.im',
    'ix.sk', 'j.gs', 'j.mp', 'ja.cat',
    'ja.ma', 'jb.gg', 'jcp.is', 'jkf.lv',
    'jnfusa.org', 'jp.rog.gg', 'jpeg.ly', 'jz.rs',
    'k-p.li', 'kas.pr', 'kask.us', 'katzr.net',
    'kbank.co', 'kck.st', 'kf.org', 'kfrc.co',
    'kg.games', 'kgs.link', 'kham.tw', 'kings.tn',
    'kkc.tech', 'kkday.me', 'kkne.ws', 'kko.to',
    'kkstre.am', 'kl.ik.my', 'klck.me', 'kli.cx',
    'klmf.ly', 'ko.gl', 'kortlink.dk', 'kotl.in',
    'kp.org', 'kpmg.ch', 'krazy.la', 'kuku.lu',
    'kurl.ru', 'kutt.it', 'ky77.link', 'l.linklyhq.com',
    'l.prageru.com', 'l8r.it', 'laco.st', 'lam.bo',
    'lat.ms', 'latingram.my', 'lativ.tw', 'lbtw.tw',
    'lc.cx', 'learn.to', 'lego.build', 'lemde.fr',
    'letsharu.cc', 'lft.to', 'lih.kg', 'lihi.biz',
    'lihi.cc', 'lihi.one', 'lihi.pro', 'lihi.tv',
    'lihi.vip', 'lihi1.cc', 'lihi1.com', 'lihi1.me',
    'lihi2.cc', 'lihi2.com', 'lihi2.me', 'lihi3.cc',
    'lihi3.com', 'lihi3.me', 'lihipro.com', 'lihivip.com',
    'liip.to', 'lin.ee', 'lin0.de', 'link.ac',
    'link.infini.fr', 'link.tubi.tv', 'linkbun.com', 'linkd.in',
    'linkjust.com', 'linko.page', 'linkopener.co', 'links2.me',
    'linkshare.pro', 'linkye.net', 'livemu.sc', 'livestre.am',
    'llk.dk', 'llo.to', 'lmg.gg', 'lmt.co',
    'lmy.de', 'ln.run', 'lnk.bz', 'lnk.direct',
    'lnk.do', 'lnk.sk', 'lnkd.in', 'lnkiy.com',
    'lnkiy.in', 'lnky.jp', 'lnnk.in', 'lnv.gy',
    'lohud.us', 'lonerwolf.co', 'loom.ly', 'low.es',
    'lprk.co', 'lru.jp', 'lsdl.es', 'lstu.fr',
    'lt27.de', 'lttr.ai', 'ludia.gg', 'luminary.link',
    'lurl.cc', 'lyksoomu.com', 'lzd.co', 'm.me',
    'm.tb.cn', 'm101.org', 'm1p.fr', 'maac.io',
    'maga.lu', 'man.ac.uk', 'many.at', 'maper.info',
    'mapfan.to', 'mayocl.in', 'mbapp.io', 'mbayaq.co',
    'mcafee.ly', 'mcd.to', 'mcgam.es', 'mck.co',
    'mcys.co', 'me.sv', 'me2.kr', 'meck.co',
    'meetu.ps', 'merky.de', 'metamark.net', 'mgnet.me',
    'mgstn.ly', 'michmed.org', 'migre.me', 'minify.link',
    'minilink.io', 'mitsha.re', 'mklnd.com', 'mm.rog.gg',
    'mney.co', 'mng.bz', 'mnge.it', 'mnot.es',
    'mo.ma', 'momo.dm', 'monster.cat', 'moo.im',
    'moovit.me', 'mork.ro', 'mou.sr', 'mpl.pm',
    'mrte.ch', 'mrx.cl', 'ms.spr.ly', 'msft.it',
    'msi.gm', 'mstr.cl', 'mttr.io', 'mub.me',
    'munbyn.biz', 'mvmtwatch.co', 'my.mtr.cool', 'mybmw.tw',
    'myglamm.in', 'mylt.tv', 'mypoya.com', 'myppt.cc',
    'mysp.ac', 'myumi.ch', 'myurls.ca', 'mz.cm',
    'mzl.la', 'n.opn.tl', 'n.pr', 'n9.cl',
    'name.ly', 'nature.ly', 'nav.cx', 'naver.me',
    'nbc4dc.com', 'nbcbay.com', 'nbcchi.com', 'nbcct.co',
    'nbcnews.to', 'nbzp.cz', 'nchcnh.info', 'nej.md',
    'neti.cc', 'netm.ag', 'nflx.it', 'ngrid.com',
    'njersy.co', 'nkbp.jp', 'nkf.re', 'nmrk.re',
    'nnn.is', 'nnna.ru', 'nokia.ly', 'notlong.com',
    'nr.tn', 'nswroads.work', 'ntap.com', 'ntck.co',
    'ntn.so', 'ntuc.co', 'nus.edu', 'nvda.ws',
    'nwppr.co', 'nwsdy.li', 'nxb.tw', 'nxdr.co',
    'nycu.to', 'nydn.us', 'nyer.cm', 'nyp.st',
    'nyr.kr', 'nyti.ms', 'o.vg', 'oal.lu',
    'obank.tw', 'ock.cn', 'ocul.us', 'oe.cd',
    'ofcour.se', 'offerup.co', 'offf.to', 'offs.ec',
    'okt.to', 'omni.ag', 'on.bcg.com', 'on.bp.com',
    'on.fb.me', 'on.ft.com', 'on.louisvuitton.com', 'on.mktw.net',
    'on.natgeo.com', 'on.nba.com', 'on.ny.gov', 'on.nyc.gov',
    'on.nypl.org', 'on.tcs.com', 'on.wsj.com', 'on9news.tv',
    'onelink.to', 'onepl.us', 'onforb.es', 'onion.com',
    'onx.la', 'oow.pw', 'opr.as', 'opr.news',
    'optimize.ly', 'oran.ge', 'orlo.uk', 'osdb.link',
    'oshko.sh', 'ouo.io', 'ouo.press', 'ourl.co',
    'ourl.in', 'ourl.tw', 'outschooler.me', 'ovh.to',
    'ow.ly', 'owl.li', 'owy.mn', 'oxelt.gl',
    'oxf.am', 'oyn.at', 'p.asia', 'p.dw.com',
    'p1r.es', 'p4k.in', 'pa.ag', 'packt.link',
    'pag.la', 'pchome.link', 'pck.tv', 'pdora.co',
    'pdxint.at', 'pe.ga', 'pens.pe', 'peoplem.ag',
    'pepsi.co', 'pesc.pw', 'petrobr.as', 'pew.org',
    'pewrsr.ch', 'pg3d.app', 'pgat.us', 'pgrs.in',
    'philips.to', 'piee.pw', 'pin.it', 'pipr.es',
    'pj.pizza', 'pl.kotl.in', 'pldthome.info', 'plu.sh',
    'pnsne.ws', 'pod.fo', 'poie.ma', 'pojonews.co',
    'politi.co', 'popm.ch', 'posh.mk', 'pplx.ai',
    'ppt.cc', 'ppurl.io', 'pr.tn', 'prbly.us',
    'prdct.school', 'preml.ge', 'prf.hn', 'prgress.co',
    'prn.to', 'propub.li', 'pros.is', 'psce.pw',
    'pse.is', 'psee.io', 'pt.rog.gg', 'ptix.co',
    'puext.in', 'purdue.university', 'purefla.sh', 'puri.na',
    'pwc.to', 'pxgo.net', 'pxu.co', 'pzdls.co',
    'q.gs', 'qnap.to', 'qptr.ru', 'qr.ae',
    'qr.net', 'qrco.de', 'qrs.ly', 'qvc.co',
    'r-7.co', 'r.zecz.ec', 'rb.gy', 'rbl.ms',
    'rblx.co', 'rch.lt', 'rd.gt', 'rdbl.co',
    'rdcrss.org', 'rdcu.be', 'read.bi', 'readhacker.news',
    'rebelne.ws', 'rebrand.ly', 'reconis.co', 'red.ht',
    'redaz.in', 'redd.it', 'redir.ec', 'redir.is',
    'redsto.ne', 'ref.trade.re', 'refini.tv', 'regmovi.es',
    'reline.cc', 'relink.asia', 'rem.ax', 'renew.ge',
    'replug.link', 'rethinktw.cc', 'reurl.cc', 'reut.rs',
    'rev.cm', 'revr.ec', 'rfr.bz', 'ringcentr.al',
    'riot.com', 'rip.city', 'risu.io', 'ritea.id',
    'rizy.ir', 'rlu.ru', 'rly.pt', 'rnm.me',
    'ro.blox.com', 'rog.gg', 'roge.rs', 'rol.st',
    'rotf.lol', 'rozhl.as', 'rpf.io', 'rptl.io',
    'rsc.li', 'rsh.md', 'rtvote.com', 'ru.rog.gg',
    'rushgiving.com', 'rvtv.io', 'rvwd.co', 'rwl.io',
    'ryml.me', 'rzr.to', 's.accupass.com', 's.coop',
    's.ee', 's.g123.jp', 's.id', 's.mj.run',
    's.ul.com', 's.uniqlo.com', 's.wikicharlie.cl', 's04.de',
    's3vip.tw', 'saf.li', 'safelinking.net', 'safl.it',
    'sail.to', 'samcart.me', 'sbird.co', 'sbux.co',
    'sbux.jp', 'sc.mp', 'sc.org', 'sched.co',
    'sck.io', 'scr.bi', 'scrb.ly', 'scuf.co',
    'sdpbne.ws', 'sdu.sk', 'sdut.us', 'se.rog.gg',
    'seagate.media', 'sealed.in', 'seedsta.rs', 'seiu.co',
    'sejr.nl', 'selnd.com', 'seq.vc', 'sf3c.tw',
    'sfca.re', 'sfcne.ws', 'sforce.co', 'sfty.io',
    'sgq.io', 'shar.as', 'shiny.link', 'shln.me',
    'sho.pe', 'shope.ee', 'shorl.com', 'short.gy',
    'shorten.asia', 'shorten.ee', 'shorten.is', 'shorten.so',
    'shorten.tv', 'shorten.world', 'shorter.me', 'shorturl.ae',
    'shorturl.asia', 'shorturl.at', 'shorturl.com', 'shorturl.gg',
    'shp.ee', 'shrtm.nu', 'sht.moe', 'shutr.bz',
    'sie.ag', 'simp.ly', 'sina.lt', 'sincere.ly',
    'sinourl.tw', 'sinyi.biz', 'sinyi.in', 'siriusxm.us',
    'siteco.re', 'sk.in.rs', 'skimmth.is', 'skl.sh',
    'skr.rs', 'skrat.it', 'skyurl.cc', 'slidesha.re',
    'small.cat', 'smart.link', 'smarturl.it', 'smashed.by',
    'smlk.es', 'smsb.co', 'smsng.news', 'smsng.us',
    'smtvj.com', 'smu.gs', 'sn.rs', 'snd.sc',
    'sndn.link', 'snip.link', 'snip.ly', 'snyk.co',
    'so.arte', 'soc.cr', 'soch.us', 'social.ora.cl',
    'socx.in', 'sokrati.ru', 'solsn.se', 'sou.nu',
    'sourl.cn', 'sovrn.co', 'spcne.ws', 'spgrp.sg',
    'spigen.co', 'split.to', 'splk.it', 'spoti.fi',
    'spotify.link', 'spr.ly', 'spr.tn', 'sprtsnt.ca',
    'sqex.to', 'sqrx.io', 'squ.re', 'srnk.us',
    'ssur.cc', 'st.news', 'st8.fm', 'stanford.io',
    'starz.tv', 'stmodel.com', 'storycor.ps', 'stspg.io',
    'stts.in', 'stuf.in', 'sumal.ly', 'suo.fyi',
    'suo.im', 'supr.cl', 'supr.link', 'surl.li',
    'svy.mk', 'swa.is', 'swag.run', 'swiy.co',
    'swoo.sh', 'swtt.cc', 'sy.to', 'syb.la',
    'synd.co', 'syw.co', 't-bi.link', 't-mo.co',
    't.cn', 't.co', 't.iotex.me', 't.libren.ms',
    't.ly', 't.me', 't.tl', 't1p.de',
    't2m.io', 'ta.co', 'tabsoft.co', 'taiwangov.com',
    'tanks.ly', 'tbb.tw', 'tbrd.co', 'tcrn.ch',
    'tdrive.li', 'tdy.sg', 'tek.io', 'temu.to',
    'ter.li', 'tg.pe', 'tgam.ca', 'tgr.ph',
    'thatis.me', 'thd.co', 'thedo.do', 'thefp.pub',
    'thein.fo', 'thesne.ws', 'thetim.es', 'thght.works',
    'thinfi.com', 'thls.co', 'thn.news', 'thr.cm',
    'thrill.to', 'ti.me', 'tibco.cm', 'tibco.co',
    'tidd.ly', 'tim.com.vc', 'tinu.be', 'tiny.cc',
    'tiny.ee', 'tiny.one', 'tiny.pl', 'tinyarro.ws',
    'tinylink.net', 'tinyurl.com', 'tinyurl.hu', 'tinyurl.mobi',
    'tktwb.tw', 'tl.gd', 'tlil.nl', 'tlrk.it',
    'tmblr.co', 'tmsnrt.rs', 'tmz.me', 'tnne.ws',
    'tnsne.ws', 'tnvge.co', 'tnw.to', 'tny.cz',
    'tny.im', 'tny.so', 'to.ly', 'to.pbs.org',
    'toi.in', 'tokopedia.link', 'tonyr.co', 'topt.al',
    'toyota.us', 'tpc.io', 'tpmr.com', 'tprk.us',
    'tr.ee', 'trackurl.link', 'trade.re', 'travl.rs',
    'trib.al', 'trib.in', 'troy.hn', 'trt.sh',
    'trymongodb.com', 'tsbk.tw', 'tsta.rs', 'tt.vg',
    'tvote.org', 'tw.rog.gg', 'tw.sv', 'twb.nz',
    'twm5g.co', 'twou.co', 'txdl.top', 'txul.cn',
    'u.nu', 'u.shxj.pw', 'u.to', 'u1.mnge.co',
    'ua.rog.gg', 'uafly.co', 'ubm.io', 'ubnt.link',
    'ubr.to', 'ucbexed.org', 'ucla.in', 'ufcqc.link',
    'ugp.io', 'ui8.ru', 'uk.rog.gg', 'ukf.me',
    'ukoeln.de', 'ul.rs', 'ul.to', 'ul3.ir',
    'ulvis.net', 'ume.la', 'umlib.us', 'unc.live',
    'undrarmr.co', 'uni.cf', 'unipapa.co', 'uofr.us',
    'uoft.me', 'up.to', 'upmchp.us', 'ur3.us',
    'urb.tf', 'urbn.is', 'url.cn', 'url.cy',
    'url.ie', 'url2.fr', 'urla.ru', 'urlgeni.us',
    'urli.ai', 'urlify.cn', 'urlr.me', 'urls.fr',
    'urls.kr', 'urluno.com', 'urly.co', 'urly.fi',
    'urlz.fr', 'urlzs.com', 'urt.io', 'us.rog.gg',
    'usanet.tv', 'usat.ly', 'utm.to', 'utn.pl',
    'utraker.com', 'v.gd', 'v.redd.it', 'vbly.us',
    'vd55.com', 'vercel.link', 'vi.sa', 'vi.tc',
    'viaalto.me', 'viaja.am', 'vineland.dj', 'viraln.co',
    'vivo.tl', 'vk.cc', 'vk.sv', 'vn.rog.gg',
    'vntyfr.com', 'vo.la', 'vodafone.uk', 'vogue.cm',
    'voicetu.be', 'volvocars.us', 'vonq.io', 'vrnda.us',
    'vtns.io', 'vur.me', 'vurl.com', 'vvnt.co',
    'vxn.link', 'vypij.bar', 'vz.to', 'w.idg.de',
    'w.wiki', 'w5n.co', 'wa.link', 'wa.me',
    'wa.sv', 'waa.ai', 'waad.co', 'wahoowa.net',
    'walk.sc', 'walkjc.org', 'wapo.st', 'warby.me',
    'warp.plus', 'wartsi.ly', 'way.to', 'wb.md',
    'wbby.co', 'wbur.fm', 'wbze.de', 'wcha.it',
    'we.co', 'weall.vote', 'weare.rs', 'wee.so',
    'wef.ch', 'wellc.me', 'wenk.io', 'wf0.xin',
    'whatel.se', 'whcs.law', 'whi.ch', 'whoel.se',
    'whr.tn', 'wi.se', 'win.gs', 'wit.to',
    'wjcf.co', 'wkf.ms', 'wmojo.com', 'wn.nr',
    'wndrfl.co', 'wo.ws', 'wooo.tw', 'wp.me',
    'wpbeg.in', 'wrctr.co', 'wrd.cm', 'wrem.it',
    'wun.io', 'ww7.fr', 'wwf.to', 'wwp.news',
    'www.shrunken.com', 'x.gd', 'xbx.lv', 'xerox.bz',
    'xfin.tv', 'xfl.ag', 'xfru.it', 'xgam.es',
    'xor.tw', 'xpr.li', 'xprt.re', 'xqss.org',
    'xrds.ca', 'xrl.us', 'xurl.es', 'xvirt.it',
    'y.ahoo.it', 'y2u.be', 'yadi.sk', 'yal.su',
    'yelp.to', 'yex.tt', 'yhoo.it', 'yip.su',
    'yji.tw', 'ynews.page.link', 'yoox.ly', 'your.ls',
    'yourls.org', 'yourwish.es', 'youtu.be', 'yubi.co',
    'yun.ir', 'z23.ru', 'zaya.io', 'zc.vg',
    'zcu.io', 'zd.net', 'zdrive.li', 'zdsk.co',
    'zecz.ec', 'zeep.ly', 'zez.kr', 'zi.ma',
    'ziadi.co', 'zipurl.fr', 'zln.do', 'zlr.my',
    'zlra.co', 'zlw.re', 'zoho.to', 'zopen.to',
    'zovpart.com', 'zpr.io', 'zuki.ie', 'zuplo.link',
    'zurb.us', 'zurins.uk', 'zurl.co', 'zurl.ir',
    'zurl.ws', 'zws.im', 'zxc.li', 'zynga.my',
    'zywv.us', 'zzb.bz', 'zzu.info',
})


def resolve_short_url(url: str, *, timeout: float = 5.0) -> Optional[str]:
    """
    Follow HTTP redirects for known URL shorteners and return the final URL.

    Uses a lightweight HEAD request (falls back to GET on 405).  Returns None
    if the URL is not a known shortener, if the redirect chain stays on the
    same apex domain, or if the network request fails.

    Used by the scoring pipeline so that t.co/bit.ly → phishing-site.xyz
    can be scored on the *destination* URL rather than the opaque short code.
    """
    try:
        apex = ".".join(urlparse(url).hostname.lower().split(".")[-2:])
    except Exception:
        return None
    if apex not in _SHORTENER_APEXES:
        return None
    try:
        import requests as _req
        sess = mount_ssrf_guard(_req.Session())
        sess.max_redirects = 10
        headers = {"User-Agent": "Mozilla/5.0 (compatible; phishing-detector/1.0)"}
        try:
            resp = sess.head(url, headers=headers, timeout=timeout, allow_redirects=True)
        except Exception:
            resp = sess.get(url, headers=headers, timeout=timeout, allow_redirects=True,
                            stream=True)
        final = resp.url
        if not final or final == url:
            return None
        final_apex = ".".join(urlparse(final).hostname.lower().split(".")[-2:])
        if final_apex == apex:
            return None  # Stayed on same domain (e.g. shortener error page)
        return final
    except Exception:
        return None


def get_geoip_city_reader():
    """Get cached GeoIP City reader."""
    global _geoip_city_reader
    if _geoip_city_reader is None and GEOIP_AVAILABLE and GEOIP_CITY_DB.exists():
        _geoip_city_reader = geoip2.database.Reader(str(GEOIP_CITY_DB))
    return _geoip_city_reader


def get_geoip_asn_reader():
    """Get cached GeoIP ASN reader."""
    global _geoip_asn_reader
    if _geoip_asn_reader is None and GEOIP_AVAILABLE and GEOIP_ASN_DB.exists():
        _geoip_asn_reader = geoip2.database.Reader(str(GEOIP_ASN_DB))
    return _geoip_asn_reader


def get_geoip_country_reader():
    """Get cached GeoIP Country reader."""
    global _geoip_country_reader
    if _geoip_country_reader is None and GEOIP_AVAILABLE and GEOIP_COUNTRY_DB.exists():
        _geoip_country_reader = geoip2.database.Reader(str(GEOIP_COUNTRY_DB))
    return _geoip_country_reader


def get_http_session():
    """Get cached HTTP session with connection pooling and limited retries."""
    global _http_session
    if _http_session is None and REQUESTS_AVAILABLE:
        _http_session = requests.Session()
        if Retry is not None:
            retry = Retry(
                total=3,
                connect=3,
                read=2,
                backoff_factor=0.25,
                status_forcelist=(429, 502, 503, 504),
                allowed_methods=("GET", "HEAD"),
            )
            adapter = SSRFGuardedAdapter(
                max_retries=retry,
                pool_connections=200,
                pool_maxsize=200,
                pool_block=False,
            )
        else:
            adapter = SSRFGuardedAdapter(
                pool_connections=200,
                pool_maxsize=200,
                max_retries=0,
                pool_block=False,
            )
        _http_session.mount("http://", adapter)
        _http_session.mount("https://", adapter)
    return _http_session


def normalize_openssl_asn1_time(value: Optional[str]) -> Optional[str]:
    """
    Convert OpenSSL ASN.1 time from ssl.SSLSocket.getpeercert() to ISO 8601 (UTC).

    Examples: 'May  6 12:00:00 2025 GMT', 'Jan  1 00:00:00 2024 GMT'
    """
    if not value or not isinstance(value, str):
        return None
    s = re.sub(r"\s+", " ", value.strip())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return value


def _flatten_whois_name_servers(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, str):
        return val.strip() or None
    parts: List[str] = []
    if isinstance(val, list):
        for item in val:
            if isinstance(item, str) and item.strip():
                parts.append(item.strip())
            elif isinstance(item, (list, tuple)) and item:
                parts.append(str(item[0]).strip())
        return ",".join(parts) if parts else None
    return str(val).strip() or None


class EnrichmentData:
    """Container for enriched data fields."""

    def __init__(self):
        # Basic
        self.url: Optional[str] = None
        self.domain: Optional[str] = None

        # Status
        self.online: Optional[str] = None
        self.http_status_code: Optional[int] = None

        # Network
        self.ip_address: Optional[str] = None
        self.cidr_block: Optional[str] = None
        self.asn: Optional[int] = None
        self.asn_name: Optional[str] = None
        self.isp: Optional[str] = None

        # Geographic
        self.country: Optional[str] = None
        self.country_name: Optional[str] = None
        self.region: Optional[str] = None
        self.city: Optional[str] = None
        self.latitude: Optional[float] = None
        self.longitude: Optional[float] = None

        # SSL/TLS
        self.ssl_enabled: Optional[str] = None
        self.cert_issuer: Optional[str] = None
        self.cert_subject: Optional[str] = None
        self.cert_valid_from: Optional[str] = None
        self.cert_valid_to: Optional[str] = None
        self.cert_serial: Optional[str] = None

        # WHOIS
        self.tld: Optional[str] = None
        self.registrar: Optional[str] = None
        self.creation_date: Optional[str] = None
        self.expiry_date: Optional[str] = None
        self.updated_date: Optional[str] = None
        self.name_servers: Optional[str] = None

        # Content
        self.page_language: Optional[str] = None
        self.page_title: Optional[str] = None
        self.form_action_domain: Optional[str] = None  # domain of primary form action (if any)
        self.final_url: Optional[str] = None  # URL after following redirects (if different)
        self.favicon_url: Optional[str] = None
        self.password_field_count: Optional[int] = None
        self.has_hidden_redirect: Optional[int] = None

        # Threat info
        self.threat_type: Optional[str] = None
        self.target_brand: Optional[str] = None
        self.threat_tags: Optional[str] = None

        # Source
        self.source_feed: Optional[str] = None
        self.source_id: Optional[str] = None

        # Timestamps
        self.first_seen: Optional[str] = None
        self.last_seen: Optional[str] = None

        # Notes
        self.notes: Optional[str] = None


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL (optimized)."""
    try:
        # Fast path: if already parsed, avoid re-parsing
        if not url:
            return None
        parsed = urlparse(url if url.startswith(
            'http') else f'http://{url}')
        return parsed.hostname
    except Exception:
        return None


def extract_tld(domain: str) -> Optional[str]:
    """Extract TLD from domain (fast path)."""
    if not domain:
        return None
    # Fast string operation instead of split
    last_dot = domain.rfind('.')
    return domain[last_dot:] if last_dot != -1 else None


def resolve_ip(domain: str) -> Optional[str]:
    """Resolve domain to IP address (with caching for speed)."""
    if not domain:
        return None
    
    # Check cache first (HUGE speedup for repeated domains)
    if domain in _dns_cache:
        cached_result = _dns_cache[domain]
        if cached_result:
            debug_logger.debug(f"resolve_ip: Cache hit for {domain} -> {cached_result}")
        return cached_result
    
    debug_logger.debug(f"resolve_ip: Looking up {domain}")
    try:
        ip = socket.gethostbyname(domain)
        _dns_cache[domain] = ip  # Cache result
        debug_logger.debug(f"resolve_ip: Success for {domain} -> {ip}")
        return ip
    except socket.gaierror as e:
        debug_logger.warning(f"resolve_ip: DNS lookup failed for {domain}: {e}")
        _dns_cache[domain] = None  # Cache failures too
        return None
    except socket.timeout as e:
        debug_logger.warning(f"resolve_ip: DNS timeout for {domain}: {e}")
        _dns_cache[domain] = None  # Cache failures too
        return None


async def resolve_ip_async(domain: str) -> Optional[str]:
    """Async DNS resolution."""
    if not domain:
        return None
    try:
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo(
            domain, None, family=socket.AF_INET,
            type=socket.SOCK_STREAM
        )
        if result:
            return result[0][4][0]
        return None
    except (socket.gaierror, socket.timeout, OSError):
        return None


def extract_base_domain(domain: str) -> str:
    """Extract base domain from subdomain."""
    if not domain:
        return domain
    
    # Multi-level TLDs like .co.uk, .ac.in, etc.
    multi_level_tlds = [
        '.co.uk', '.ac.uk', '.gov.uk', '.org.uk',
        '.co.in', '.ac.in', '.gov.in',
        '.co.jp', '.ac.jp', '.go.jp',
        '.com.au', '.gov.au', '.edu.au',
        '.co.nz', '.govt.nz', '.ac.nz',
    ]
    
    domain_lower = domain.lower()
    for tld in multi_level_tlds:
        if domain_lower.endswith(tld):
            # Get the part before this TLD
            prefix = domain[:-(len(tld))]
            # Split the prefix and take the last part
            if '.' in prefix:
                base_name = prefix.rsplit('.', 1)[-1]
                return base_name + tld
            # No subdomain, return as is
            return domain
    
    # Standard TLD case (e.g., .com, .org, .net)
    parts = domain.split('.')
    if len(parts) > 2:
        # Return last two parts (example.com from mail.example.com)
        return '.'.join(parts[-2:])
    
    return domain


def _whois_lookup_once(domain: str) -> Dict[str, Any]:
    """Single WHOIS query; returns empty dict on failure."""
    if not WHOIS_AVAILABLE or not domain:
        return {}
    try:
        base_domain = extract_base_domain(domain)
        w = whois.whois(base_domain)

        def extract_date(date_val: Any) -> Optional[str]:
            if date_val is None:
                return None
            if isinstance(date_val, list):
                date_val = date_val[0] if date_val else None
            if isinstance(date_val, datetime):
                return date_val.replace(tzinfo=timezone.utc).isoformat()
            if isinstance(date_val, str) and date_val.strip():
                return date_val.strip()
            return None

        def extract_string(val: Any) -> Optional[str]:
            if val is None:
                return None
            if isinstance(val, list):
                val = val[0] if val else None
            return str(val).strip() if val else None

        return {
            "registrar": extract_string(w.registrar),
            "creation_date": extract_date(w.creation_date),
            "expiry_date": extract_date(w.expiration_date),
            "updated_date": extract_date(w.updated_date),
            "name_servers": _flatten_whois_name_servers(w.name_servers),
        }
    except Exception:
        return {}


def get_whois_info(domain: str) -> Dict[str, Any]:
    """Get WHOIS information for domain (retries + fallback query)."""
    if not WHOIS_AVAILABLE or not domain:
        return {}

    base_domain = extract_base_domain(domain)
    candidates = [base_domain]
    if domain.strip().lower() != base_domain.strip().lower():
        candidates.append(domain.strip())

    last: Dict[str, Any] = {}
    for qdom in candidates:
        for attempt in range(3):
            info = _whois_lookup_once(qdom)
            if info and any(
                info.get(k) for k in ("registrar", "creation_date", "name_servers")
            ):
                return info
            last = info or last
            if attempt < 2:
                time.sleep(0.45)
    return last


def get_geoip_info(ip_address: str) -> Dict[str, Any]:
    """Get GeoIP information for IP address (using cached readers)."""
    if not ip_address:
        debug_logger.debug(f"get_geoip_info: No IP address provided")
        return {}

    result = {}
    debug_logger.debug(f"get_geoip_info: Starting lookup for {ip_address}")

    # Try GeoIP databases if available (use cached readers for speed)
    if GEOIP_AVAILABLE:
        # Try City database
        city_reader = get_geoip_city_reader()
        if city_reader:
            try:
                response = city_reader.city(ip_address)
                result.update({
                    'country': response.country.iso_code,
                    'country_name': response.country.name,
                    'region': response.subdivisions.most_specific.name
                    if response.subdivisions else None,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                })
                debug_logger.debug(f"get_geoip_info: City lookup successful for {ip_address} - {result.get('country')}")
            except geoip2.errors.AddressNotFoundError as e:
                debug_logger.debug(f"get_geoip_info: Address not found in City DB for {ip_address}")
            except Exception as e:
                debug_logger.warning(f"get_geoip_info: City lookup failed for {ip_address}: {type(e).__name__}: {e}")
        else:
            debug_logger.debug(f"get_geoip_info: No City reader available")
        
        # If no country from City DB, try Country database
        if not result.get('country'):
            country_reader = get_geoip_country_reader()
            if country_reader:
                try:
                    response = country_reader.country(ip_address)
                    result.update({
                        'country': response.country.iso_code,
                        'country_name': response.country.name,
                    })
                    debug_logger.debug(f"get_geoip_info: Country lookup successful for {ip_address} - {result.get('country')}")
                except geoip2.errors.AddressNotFoundError as e:
                    debug_logger.debug(f"get_geoip_info: Address not found in Country DB for {ip_address}")
                except Exception as e:
                    debug_logger.warning(f"get_geoip_info: Country lookup failed for {ip_address}: {type(e).__name__}: {e}")

        # Try ASN database
        asn_reader = get_geoip_asn_reader()
        if asn_reader:
            try:
                response = asn_reader.asn(ip_address)
                result.update({
                    'asn': response.autonomous_system_number,
                    'asn_name': response.autonomous_system_organization,
                })
                debug_logger.debug(f"get_geoip_info: ASN lookup successful for {ip_address} - AS{result.get('asn')} {result.get('asn_name')}")
            except geoip2.errors.AddressNotFoundError as e:
                debug_logger.debug(f"get_geoip_info: Address not found in ASN DB for {ip_address}")
            except Exception as e:
                debug_logger.warning(f"get_geoip_info: ASN lookup failed for {ip_address}: {type(e).__name__}: {e}")
        else:
            debug_logger.debug(f"get_geoip_info: No ASN reader available")
    else:
        debug_logger.debug(f"get_geoip_info: GeoIP not available")

    # Fallback to free IP-API service if we don't have GeoIP data
    if not result and REQUESTS_AVAILABLE:
        debug_logger.debug(f"get_geoip_info: Trying IP-API fallback for {ip_address}")
        try:
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            debug_logger.debug(f"get_geoip_info: IP-API response status {response.status_code} for {ip_address}")
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result.update({
                        'country': data.get('countryCode'),
                        'country_name': data.get('country'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'asn': int(data.get('as', '').split()[0].replace(
                            'AS', '')) if data.get('as') else None,
                        'asn_name': ' '.join(data.get('as', '').split()[
                            1:]) if data.get('as') else None,
                        'isp': data.get('isp'),
                    })
                    debug_logger.debug(f"get_geoip_info: IP-API success for {ip_address} - {result}")
                    time.sleep(0.5)  # Rate limit for free API
                else:
                    debug_logger.warning(f"get_geoip_info: IP-API returned failure status for {ip_address}: {data}")
        except Exception as e:
            debug_logger.warning(f"get_geoip_info: IP-API exception for {ip_address}: {type(e).__name__}: {e}")

    if not result:
        debug_logger.warning(f"get_geoip_info: No GeoIP data found for {ip_address}")
    
    return result


def get_asn_info_ipwhois(ip_address: str) -> Dict[str, Any]:
    """Get ASN/ISP information using IPWhois (fallback method)."""
    if not IPWHOIS_AVAILABLE:
        debug_logger.debug(f"get_asn_info_ipwhois: IPWhois not available")
        return {}
    
    if not ip_address:
        debug_logger.debug(f"get_asn_info_ipwhois: No IP address provided")
        return {}

    debug_logger.debug(f"get_asn_info_ipwhois: Starting RDAP lookup for {ip_address}")
    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap(depth=1)
        
        parsed_result = {
            'asn': int(result.get('asn', '').replace(
                'AS', '')) if result.get('asn') else None,
            'asn_name': result.get('asn_description'),
            'cidr_block': result.get('network', {}).get('cidr'),
            'isp': result.get('network', {}).get('name'),
            'country': result.get('asn_country_code'),
        }
        debug_logger.debug(f"get_asn_info_ipwhois: Success for {ip_address} - AS{parsed_result.get('asn')} {parsed_result.get('asn_name')}")
        return parsed_result
    except Exception as e:
        debug_logger.warning(f"get_asn_info_ipwhois: Failed for {ip_address}: {type(e).__name__}: {e}")
        return {}


def get_ssl_info(domain: str) -> Dict[str, Any]:
    """Get SSL certificate information."""
    if not domain:
        return {}

    try:
        context = ssl.create_default_context()
        # SSRF-guarded: resolves + filters non-public IPs, dials literal IP.
        # server_hostname=domain preserves SNI / cert validation against the
        # caller's intended name.
        with safe_create_connection(
                (domain, 443), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Extract issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_str = issuer.get(
                    'organizationName',
                    issuer.get('commonName', '')
                )

                # Extract subject
                subject = dict(x[0] for x in cert.get('subject', []))
                subject_str = subject.get('commonName', '')

                return {
                    'ssl_enabled': 'yes',
                    'cert_issuer': issuer_str,
                    'cert_subject': subject_str,
                    'cert_valid_from': normalize_openssl_asn1_time(
                        cert.get('notBefore')
                    ),
                    'cert_valid_to': normalize_openssl_asn1_time(
                        cert.get('notAfter')
                    ),
                    'cert_serial': cert.get('serialNumber'),
                }
    except (socket.timeout, ssl.SSLError, Exception):
        return {'ssl_enabled': 'no'}


async def get_ssl_info_async(domain: str) -> Dict[str, Any]:
    """Async SSL certificate check."""
    if not domain:
        return {}
    
    try:
        loop = asyncio.get_event_loop()
        # Run blocking SSL check in thread pool
        return await loop.run_in_executor(None, get_ssl_info, domain)
    except Exception:
        return {'ssl_enabled': 'no'}


def get_page_content(url: str) -> Dict[str, Any]:
    """Get page content including title and language (uses cached session)."""
    if not REQUESTS_AVAILABLE or not url:
        return {}

    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        session = get_http_session()
        if not session:
            return {}

        response = session.get(
            url,
            timeout=PAGE_CONTENT_TIMEOUT,
            allow_redirects=True,
            verify=False,
            headers={
                'User-Agent': _DEFAULT_BROWSER_UA,
                'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            },
        )

        result: Dict[str, Any] = {
            'online': 'yes' if response.status_code < 400 else 'no',
            'http_status_code': response.status_code,
        }

        # Track final URL after redirects (for shortener resolution)
        final = response.url
        if final and final != url:
            result['final_url'] = final

        title_match = _TITLE_REGEX.search(response.text)
        if title_match:
            result['page_title'] = title_match.group(1).strip()[:200]

        lang_match = _LANG_REGEX.search(response.text)
        if lang_match:
            result['page_language'] = lang_match.group(1)

        # Extract primary form action domain (phishing signal: form submits to different domain)
        form_match = _FORM_ACTION_REGEX.search(response.text)
        if form_match:
            action = form_match.group(1).strip()
            try:
                parsed_action = urlparse(action if '://' in action else f'https:{action}' if action.startswith('//') else None or action)
                action_host = parsed_action.hostname
                if action_host:
                    result['form_action_domain'] = action_host
            except Exception:
                pass

        # DOM credential signals
        favicon_match = _FAVICON_REGEX.search(response.text)
        if favicon_match:
            fav_url = favicon_match.group(1) or favicon_match.group(2)
            if fav_url:
                result['favicon_url'] = fav_url.strip()[:200]

        pw_matches = _PASSWORD_FIELD_REGEX.findall(response.text)
        result['password_field_count'] = len(pw_matches)

        hidden_match = _HIDDEN_REDIRECT_REGEX.search(response.text)
        result['has_hidden_redirect'] = 1 if hidden_match else 0

        return result

    except requests.exceptions.SSLError:
        try:
            url_http = url.replace('https://', 'http://')
            response = session.get(
                url_http,
                timeout=PAGE_CONTENT_TIMEOUT,
                allow_redirects=True,
                headers={'User-Agent': _DEFAULT_BROWSER_UA},
            )
            return {
                'online': 'yes' if response.status_code < 400 else 'no',
                'http_status_code': response.status_code,
                '_fetch_error': 'ssl_fallback_http',
            }
        except requests.exceptions.Timeout:
            return {'online': 'unknown', 'http_status_code': None, '_fetch_error': 'timeout_after_ssl'}
        except Exception:
            return {'online': 'no', 'http_status_code': None, '_fetch_error': 'ssl_fallback_failed'}
    except requests.exceptions.Timeout:
        return {'online': 'unknown', 'http_status_code': None, '_fetch_error': 'timeout'}
    except requests.exceptions.ConnectionError:
        return {'online': 'no', 'http_status_code': None, '_fetch_error': 'connection_error'}
    except Exception:
        return {'online': 'unknown', 'http_status_code': None, '_fetch_error': 'error'}


def check_online_status(url: str) -> Tuple[Optional[str], Optional[int]]:
    """Check if URL is online and get HTTP status (lightweight HEAD request)."""
    if not REQUESTS_AVAILABLE or not url:
        return None, None

    try:
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'

        session = get_http_session()
        if not session:
            return None, None
        
        response = session.head(
            url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=False  # Skip SSL verification for phishing sites
        )
        return 'yes', response.status_code
    except requests.exceptions.SSLError:
        # Try without SSL — reuse the SSRF-guarded shared session.
        try:
            url = url.replace('https://', 'http://')
            response = session.head(
                url, timeout=HTTP_TIMEOUT, allow_redirects=True)
            return 'yes', response.status_code
        except Exception:
            return 'no', None
    except requests.exceptions.Timeout:
        return 'unknown', None
    except requests.exceptions.ConnectionError:
        return 'no', None
    except Exception:
        return 'unknown', None


async def check_online_status_async(url: str) -> Tuple[Optional[str], Optional[int]]:
    """Async online status check (ULTRA fast with aggressive timeouts)."""
    if not url:
        return None, None
    
    # Use aiohttp if available for true async
    if AIOHTTP_AVAILABLE:
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            # ULTRA aggressive timeout
            timeout = aiohttp.ClientTimeout(
                total=HTTP_TIMEOUT,
                connect=0.5,  # Fast connection timeout
                sock_read=0.5  # Fast read timeout
            )
            # Reuse connector for better performance.
            # SSRFGuardedConnector overrides _resolve_host to reject resolved
            # IPs in loopback/link-local/private/multicast/reserved blocks
            # (incl. 169.254.169.254 cloud metadata) before the dial.
            connector = SSRFGuardedConnector(
                limit=200,  # High connection limit
                ttl_dns_cache=300,  # Cache DNS for 5 min
                force_close=False,  # Keep connections alive
                enable_cleanup_closed=True
            )
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector
            ) as session:
                async with session.head(
                    url,
                    allow_redirects=True,
                    ssl=False  # Skip SSL verification
                ) as response:
                    return 'yes', response.status
        except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
            # Fast fail - don't retry
            return 'no', None
    
    # Fallback to requests in thread pool
    if REQUESTS_AVAILABLE:
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, check_online_status, url)
        except Exception:
            return 'unknown', None
    
    return None, None


def enrich_url(
        url: str,
        source_feed: str,
        source_id: Optional[str] = None,
        existing_data: Optional[Dict[str, Any]] = None
) -> EnrichmentData:
    """
    Enrich a single URL with all available data sources.

    Args:
        url: The URL to enrich
        source_feed: Source feed name
        source_id: Original ID from source feed
        existing_data: Any existing data from raw database

    Returns:
        EnrichmentData object with all enriched fields
    """
    data = EnrichmentData()
    data.url = url
    data.source_feed = source_feed
    data.source_id = source_id

    # Extract domain
    data.domain = extract_domain(url)
    if not data.domain:
        return data

    data.tld = extract_tld(data.domain)

    # Copy existing data from raw database if available
    if existing_data:
        data.target_brand = existing_data.get('target')
        data.threat_tags = existing_data.get('tags')
        data.threat_type = existing_data.get('threat')
        data.online = existing_data.get('online')
        data.ip_address = existing_data.get('ip_address')
        data.cidr_block = existing_data.get('cidr_block')
        data.asn = existing_data.get('asn')
        data.country = existing_data.get('country')

    # Resolve IP if not already available
    if not data.ip_address:
        data.ip_address = resolve_ip(data.domain)

    # Get WHOIS information
    whois_info = get_whois_info(data.domain)
    if whois_info:
        data.registrar = whois_info.get('registrar')
        data.creation_date = whois_info.get('creation_date')
        data.expiry_date = whois_info.get('expiry_date')
        data.updated_date = whois_info.get('updated_date')
        data.name_servers = whois_info.get('name_servers')

    # Get GeoIP information
    if data.ip_address:
        geoip_info = get_geoip_info(data.ip_address)
        if geoip_info:
            data.country = data.country or geoip_info.get('country')
            data.country_name = geoip_info.get('country_name')
            data.region = geoip_info.get('region')
            data.city = geoip_info.get('city')
            data.latitude = geoip_info.get('latitude')
            data.longitude = geoip_info.get('longitude')
            data.asn = data.asn or geoip_info.get('asn')
            data.asn_name = geoip_info.get('asn_name')

        # Use IPWhois to fill missing ASN or CIDR info
        if IPWHOIS_AVAILABLE and (not data.asn or not data.cidr_block):
            asn_info = get_asn_info_ipwhois(data.ip_address)
            if asn_info:
                data.asn = data.asn or asn_info.get('asn')
                data.asn_name = data.asn_name or asn_info.get('asn_name')
                data.cidr_block = data.cidr_block or asn_info.get(
                    'cidr_block')
                data.isp = data.isp or asn_info.get('isp')
                data.country = data.country or asn_info.get('country')

    # Get SSL certificate information
    ssl_info = get_ssl_info(data.domain)
    if ssl_info:
        data.ssl_enabled = ssl_info.get('ssl_enabled')
        data.cert_issuer = ssl_info.get('cert_issuer')
        data.cert_subject = ssl_info.get('cert_subject')
        data.cert_valid_from = ssl_info.get('cert_valid_from')
        data.cert_valid_to = ssl_info.get('cert_valid_to')
        data.cert_serial = ssl_info.get('cert_serial')

    # Get page content (title, language, online status)
    if not data.online or not data.page_title:
        page_info = get_page_content(url)
        if page_info:
            data.online = data.online or page_info.get('online')
            data.http_status_code = page_info.get('http_status_code')
            data.page_title = page_info.get('page_title')
            data.page_language = page_info.get('page_language')
            data.form_action_domain = page_info.get('form_action_domain')
            data.favicon_url = page_info.get('favicon_url')
            data.password_field_count = page_info.get('password_field_count')
            data.has_hidden_redirect = page_info.get('has_hidden_redirect')
            if page_info.get('final_url'):
                data.final_url = page_info['final_url']
            err = page_info.get('_fetch_error')
            if err:
                data.notes = (
                    (data.notes + ';') if data.notes else ''
                ) + f'page_fetch:{err}'

    # Fallback lightweight online check if still no status
    if not data.online:
        online_status, http_code = check_online_status(url)
        data.online = online_status
        data.http_status_code = data.http_status_code or http_code

    # Fill ISP from ASN name if not already set
    if not data.isp and data.asn_name:
        data.isp = data.asn_name

    # Infer threat_type from source feed if not set
    if not data.threat_type:
        if source_feed == 'phishtank' or source_feed == 'openphish':
            data.threat_type = 'phishing'
        elif source_feed == 'urlhaus':
            data.threat_type = data.threat_type or 'malware'
        elif source_feed == 'tranco_ml_benign':
            data.threat_type = 'benign'

    # Try to detect language from page title if language is missing
    if not data.page_language and data.page_title:
        if LANGDETECT_AVAILABLE:
            try:
                # Use langdetect for accurate language detection
                detected_lang = detect(data.page_title)
                data.page_language = detected_lang
            except LangDetectException:
                pass
        else:
            # Fallback: Simple heuristic-based language detection
            title_lower = data.page_title.lower()
            if any(word in title_lower for word in
                   ['sign', 'login', 'account', 'verify',
                    'update', 'security']):
                data.page_language = 'en'
            elif any(word in title_lower for word in
                     ['iniciar', 'cuenta', 'verificar', 'actualizar']):
                data.page_language = 'es'
            elif any(word in title_lower for word in
                     ['connexion', 'compte', 'vérifier', 'mettre']):
                data.page_language = 'fr'
            elif any(word in title_lower for word in
                     ['anmelden', 'konto', 'überprüfen',
                      'aktualisieren']):
                data.page_language = 'de'
            elif any(word in title_lower for word in
                     ['accesso', 'conto', 'verificare', 'aggiornare']):
                data.page_language = 'it'

    # Fill country_name from country code if missing
    if data.country and not data.country_name:
        country_names = {
            'US': 'United States', 'CN': 'China', 'RU': 'Russia',
            'DE': 'Germany', 'GB': 'United Kingdom', 'FR': 'France',
            'JP': 'Japan', 'KR': 'South Korea', 'IN': 'India',
            'BR': 'Brazil', 'CA': 'Canada', 'AU': 'Australia',
            'NL': 'Netherlands', 'IT': 'Italy', 'ES': 'Spain',
            'SE': 'Sweden', 'PL': 'Poland', 'TR': 'Turkey',
            'MX': 'Mexico', 'ID': 'Indonesia', 'TH': 'Thailand',
            'VN': 'Vietnam', 'PH': 'Philippines', 'MY': 'Malaysia',
            'SG': 'Singapore', 'HK': 'Hong Kong', 'TW': 'Taiwan',
        }
        data.country_name = country_names.get(data.country, data.country)

    # Set timestamps
    data.last_seen = datetime.now(timezone.utc).isoformat()

    return data


async def enrich_url_async(
        url: str,
        source_feed: str,
        source_id: Optional[str] = None,
        existing_data: Optional[Dict[str, Any]] = None,
        executor: Optional[ThreadPoolExecutor] = None,
        enable_whois: bool = True,  # Enabled by default
        enable_ipwhois: bool = True,  # Enabled by default
        enable_page_content: bool = True  # Enabled by default
) -> EnrichmentData:
    """
    HYPER-OPTIMIZED async enrichment with MAXIMUM parallelism.
    
    ALL network operations run in parallel - no sequential waits!
    - DNS, SSL, HTTP, WHOIS, IPWhois all start simultaneously
    - Uses async I/O where possible (aiohttp, async DNS)
    - Thread pool only for truly blocking operations (WHOIS, IPWhois)
    - Cached readers for GeoIP (no file reopening)
    """
    debug_logger.debug(f"enrich_url_async: Starting enrichment for {url}")
    
    data = EnrichmentData()
    data.url = url
    data.source_feed = source_feed
    data.source_id = source_id

    # Extract domain (sync, instant)
    data.domain = extract_domain(url)
    if not data.domain:
        debug_logger.warning(f"enrich_url_async: Failed to extract domain from {url}")
        return data

    data.tld = extract_tld(data.domain)
    debug_logger.debug(f"enrich_url_async: Domain={data.domain}, TLD={data.tld}")

    # Copy existing data from raw database if available
    if existing_data:
        data.target_brand = existing_data.get('target')
        data.threat_tags = existing_data.get('tags')
        data.threat_type = existing_data.get('threat')
        data.online = existing_data.get('online')
        data.ip_address = existing_data.get('ip_address')
        data.cidr_block = existing_data.get('cidr_block')
        data.asn = existing_data.get('asn')
        data.country = existing_data.get('country')

    loop = asyncio.get_event_loop()
    
    # ========================================================================
    # PHASE 1: Start ALL operations in parallel (no waits!)
    # ========================================================================
    
    # DNS resolution (async, needed for other operations)
    dns_task = None
    if not data.ip_address:
        dns_task = resolve_ip_async(data.domain)
    
    # WHOIS lookup (blocking, in thread pool) - OPTIONAL (slow!)
    whois_task = None
    if enable_whois and WHOIS_AVAILABLE:
        whois_task = loop.run_in_executor(
            executor, get_whois_info, data.domain
        )
    
    # SSL check (async I/O) - can run independently
    ssl_task = get_ssl_info_async(data.domain)
    
    # Online check (async I/O) - can run independently
    online_task = None
    if not data.online:
        online_task = check_online_status_async(url)
    
    # Page content (title, language) - ENABLED by default (can disable)
    page_task = None
    if enable_page_content and not data.page_title:
        page_task = loop.run_in_executor(
            executor, get_page_content, url
        )
    
    # ========================================================================
    # PHASE 2: Wait for DNS first (needed for GeoIP and IPWhois)
    # ========================================================================
    
    if dns_task:
        data.ip_address = await dns_task
        if data.ip_address:
            debug_logger.debug(f"enrich_url_async: DNS resolved {data.domain} -> {data.ip_address}")
        else:
            debug_logger.warning(f"enrich_url_async: DNS resolution failed for {data.domain}")
    
    # ========================================================================
    # PHASE 3: Start IP-dependent operations in parallel
    # ========================================================================
    
    # GeoIP lookup (sync but fast with cached readers)
    geoip_task = None
    if data.ip_address:
        # Run GeoIP in thread pool to not block event loop
        debug_logger.debug(f"enrich_url_async: Starting GeoIP lookup for {data.ip_address}")
        geoip_task = loop.run_in_executor(
            executor, get_geoip_info, data.ip_address
        )
    else:
        debug_logger.debug(f"enrich_url_async: Skipping GeoIP - no IP address for {data.domain}")
    
    # IPWhois lookup (blocking, in thread pool) - OPTIONAL (can be slow!)
    ipwhois_task = None
    if (enable_ipwhois and data.ip_address and IPWHOIS_AVAILABLE and
            (not data.asn or not data.cidr_block)):
        debug_logger.debug(f"enrich_url_async: Starting IPWhois lookup for {data.ip_address}")
        ipwhois_task = loop.run_in_executor(
            executor, get_asn_info_ipwhois, data.ip_address
        )
    else:
        if not enable_ipwhois:
            debug_logger.debug(f"enrich_url_async: IPWhois disabled")
        elif not data.ip_address:
            debug_logger.debug(f"enrich_url_async: Skipping IPWhois - no IP address")
        elif not IPWHOIS_AVAILABLE:
            debug_logger.debug(f"enrich_url_async: IPWhois not available")
        else:
            debug_logger.debug(f"enrich_url_async: Skipping IPWhois - already have ASN={data.asn} CIDR={data.cidr_block}")
    
    # ========================================================================
    # PHASE 4: Gather ALL results in parallel (asyncio.gather)
    # ========================================================================
    
    # Collect all pending tasks (build list dynamically)
    pending_tasks = []
    task_map = {}  # Track what each index represents
    
    if whois_task:
        task_map[len(pending_tasks)] = 'whois'
        pending_tasks.append(whois_task)
    
    task_map[len(pending_tasks)] = 'ssl'
    pending_tasks.append(ssl_task)
    
    if online_task:
        task_map[len(pending_tasks)] = 'online'
        pending_tasks.append(online_task)
    
    if page_task:
        task_map[len(pending_tasks)] = 'page'
        pending_tasks.append(page_task)
    
    if geoip_task:
        task_map[len(pending_tasks)] = 'geoip'
        pending_tasks.append(geoip_task)
    
    if ipwhois_task:
        task_map[len(pending_tasks)] = 'ipwhois'
        pending_tasks.append(ipwhois_task)
    
    # Wait for ALL tasks to complete in parallel
    debug_logger.debug(f"enrich_url_async: Waiting for {len(pending_tasks)} tasks for {data.domain}")
    results = await asyncio.gather(*pending_tasks, return_exceptions=True)
    debug_logger.debug(f"enrich_url_async: All tasks completed for {data.domain}")
    
    # ========================================================================
    # PHASE 5: Process results (using task_map for correct indexing)
    # ========================================================================
    
    # Parse results based on task_map
    for idx, task_type in task_map.items():
        if idx >= len(results):
            continue
        
        result = results[idx]
        if isinstance(result, Exception):
            debug_logger.warning(f"enrich_url_async: Task {task_type} failed for {data.domain}: {type(result).__name__}: {result}")
            continue
        
        if task_type == 'whois' and result:
            data.registrar = result.get('registrar')
            data.creation_date = result.get('creation_date')
            data.expiry_date = result.get('expiry_date')
            data.updated_date = result.get('updated_date')
            data.name_servers = result.get('name_servers')
        
        elif task_type == 'ssl' and result:
            data.ssl_enabled = result.get('ssl_enabled')
            data.cert_issuer = result.get('cert_issuer')
            data.cert_subject = result.get('cert_subject')
            data.cert_valid_from = result.get('cert_valid_from')
            data.cert_valid_to = result.get('cert_valid_to')
            data.cert_serial = result.get('cert_serial')
        
        elif task_type == 'online' and result:
            data.online, data.http_status_code = result
        
        elif task_type == 'page' and result:
            data.online = data.online or result.get('online')
            data.http_status_code = (data.http_status_code or
                                    result.get('http_status_code'))
            data.page_title = result.get('page_title')
            data.page_language = result.get('page_language')
            data.form_action_domain = result.get('form_action_domain')
            data.favicon_url = result.get('favicon_url')
            data.password_field_count = result.get('password_field_count')
            data.has_hidden_redirect = result.get('has_hidden_redirect')
            if result.get('final_url'):
                data.final_url = result['final_url']
            err = result.get('_fetch_error')
            if err:
                data.notes = (
                    (data.notes + ';') if data.notes else ''
                ) + f'page_fetch:{err}'
        
        elif task_type == 'geoip' and result:
            debug_logger.debug(f"enrich_url_async: Processing GeoIP result for {data.domain}: {result}")
            data.country = data.country or result.get('country')
            data.country_name = result.get('country_name')
            data.region = result.get('region')
            data.city = result.get('city')
            data.latitude = result.get('latitude')
            data.longitude = result.get('longitude')
            data.asn = data.asn or result.get('asn')
            data.asn_name = result.get('asn_name')
            if not result:
                debug_logger.warning(f"enrich_url_async: GeoIP returned empty result for {data.ip_address}")
        
        elif task_type == 'ipwhois' and result:
            debug_logger.debug(f"enrich_url_async: Processing IPWhois result for {data.domain}: {result}")
            data.asn = data.asn or result.get('asn')
            data.asn_name = data.asn_name or result.get('asn_name')
            data.cidr_block = data.cidr_block or result.get('cidr_block')
            data.isp = data.isp or result.get('isp')
            data.country = data.country or result.get('country')
            if not result:
                debug_logger.warning(f"enrich_url_async: IPWhois returned empty result for {data.ip_address}")
    
    # ========================================================================
    # PHASE 6: Post-processing and inference
    # ========================================================================

    # Fill ISP from ASN name if not already set
    if not data.isp and data.asn_name:
        data.isp = data.asn_name
    
    # Infer threat_type from source feed if not set
    if not data.threat_type:
        if source_feed in ('phishtank', 'openphish'):
            data.threat_type = 'phishing'
        elif source_feed == 'urlhaus':
            data.threat_type = 'malware'
        elif source_feed == 'tranco_ml_benign':
            data.threat_type = 'benign'

    # Fill country_name from country code if missing
    if data.country and not data.country_name:
        country_names = {
            'US': 'United States', 'CN': 'China', 'RU': 'Russia',
            'DE': 'Germany', 'GB': 'United Kingdom', 'FR': 'France',
            'JP': 'Japan', 'KR': 'South Korea', 'IN': 'India',
            'BR': 'Brazil', 'CA': 'Canada', 'AU': 'Australia',
            'NL': 'Netherlands', 'IT': 'Italy', 'ES': 'Spain',
            'SE': 'Sweden', 'PL': 'Poland', 'TR': 'Turkey',
            'MX': 'Mexico', 'ID': 'Indonesia', 'TH': 'Thailand',
            'VN': 'Vietnam', 'PH': 'Philippines', 'MY': 'Malaysia',
            'SG': 'Singapore', 'HK': 'Hong Kong', 'TW': 'Taiwan',
        }
        data.country_name = country_names.get(data.country, data.country)
    
    # Set timestamps
    data.last_seen = datetime.now(timezone.utc).isoformat()
    
    # Final debug summary for this URL
    debug_logger.debug(
        f"enrich_url_async: Completed {url} - "
        f"IP={data.ip_address}, ASN={data.asn}, ISP={data.isp}, "
        f"Country={data.country}, Online={data.online}"
    )
    
    # Log warning if critical data is missing
    if data.ip_address and not data.asn:
        debug_logger.warning(f"enrich_url_async: Missing ASN for {url} (IP: {data.ip_address})")
    if data.ip_address and not data.isp:
        debug_logger.warning(f"enrich_url_async: Missing ISP for {url} (IP: {data.ip_address})")
    
    return data


def get_raw_data(
        raw_db_path: Path
) -> List[Tuple[str, str, Optional[str], Dict[str, Any]]]:
    """
    Fetch URLs from raw database that need enrichment.

    Returns:
        List of (url, source_feed, source_id, existing_data) tuples
    """
    con = sqlite3.connect(str(raw_db_path))
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    results: List[Tuple[str, str, Optional[str], Dict[str, Any]]] = []

    # ML benign (Tranco / manual) — **first** so PhishTank/OpenPhish/URLhaus rows that share
    # the same URL overwrite via INSERT OR REPLACE and keep threat semantics.
    try:
        cur.execute("""
            SELECT id, url, tranco_rank, stratum, benign_source
            FROM ml_benign_urls
        """)
        for row in cur.fetchall():
            results.append(
                (
                    row["url"],
                    "tranco_ml_benign",
                    str(row["id"]),
                    {
                        "tranco_rank": row["tranco_rank"],
                        "stratum": row["stratum"],
                        "benign_source": row["benign_source"],
                    },
                )
            )
    except sqlite3.OperationalError:
        pass

    # OpenPhish: table is refreshed to match the live feed snapshot (see grabrawdata).
    # Prefer higher row id (later lines in the feed insert batch) when sampling.
    cur.execute("SELECT url, domain FROM openphish_feed ORDER BY id DESC")
    for row in cur.fetchall():
        results.append((
            row['url'],
            'openphish',
            None,
            {'domain': row['domain']}
        ))

    # PhishTank: only **online-valid** snapshot rows (online = yes) kept in raw DB.
    cur.execute("""
        SELECT phish_id, url, online, target, ip_address,
               cidr_block, announcing_network, rir
        FROM phishtank_archival
        WHERE online = 'yes'
        ORDER BY submission_time DESC
    """)
    for row in cur.fetchall():
        # Parse ASN from announcing_network if it's a number
        asn = None
        if row['announcing_network']:
            try:
                asn = int(str(row['announcing_network']).replace('AS', '').strip())
            except (ValueError, AttributeError):
                asn = None

        results.append((
            row['url'],
            'phishtank',
            str(row['phish_id']),
            {
                'online': row['online'],
                'target': row['target'],
                'ip_address': row['ip_address'],
                'cidr_block': row['cidr_block'],
                'asn': asn,
                'rir': row['rir'],
            }
        ))

    # Get URLhaus data
    cur.execute("""
        SELECT url, threat, tags, asn, country
        FROM urlhaus_api
    """)
    for row in cur.fetchall():
        results.append((
            row['url'],
            'urlhaus',
            None,
            {
                'threat': row['threat'],
                'tags': row['tags'],
                'asn': row['asn'],
                'country': row['country'],
            }
        ))

    cur.close()
    con.close()

    logger.info(f"Found {len(results)} URLs to enrich from raw database")
    return results


def insert_enriched_data(enriched_db_path: Path, data: EnrichmentData):
    """Insert enriched data into the database.
    
    IMPORTANT: Uses INSERT OR IGNORE to prevent overwriting existing entries.
    This preserves threat feed data when the same URL is seen from email sources.
    """
    con = sqlite3.connect(str(enriched_db_path))
    cur = con.cursor()

    # Changed from INSERT OR REPLACE to INSERT OR IGNORE
    # This prevents overwriting threat feed entries with email source data
    cur.execute("""
        INSERT OR IGNORE INTO enriched_threats (
            url, domain, online, http_status_code,
            ip_address, cidr_block, asn, asn_name, isp,
            country, country_name, region, city, latitude, longitude,
            ssl_enabled, cert_issuer, cert_subject,
            cert_valid_from, cert_valid_to, cert_serial,
            tld, registrar, creation_date, expiry_date,
            updated_date, name_servers,
            page_language, page_title,
            threat_type, target_brand, threat_tags,
            source_feed, source_id, last_seen, last_checked,
            notes, updated_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, datetime('now'), ?, datetime('now')
        )
    """, (
        data.url, data.domain, data.online, data.http_status_code,
        data.ip_address, data.cidr_block, data.asn, data.asn_name, data.isp,
        data.country, data.country_name, data.region, data.city,
        data.latitude, data.longitude,
        data.ssl_enabled, data.cert_issuer, data.cert_subject,
        data.cert_valid_from, data.cert_valid_to, data.cert_serial,
        data.tld, data.registrar, data.creation_date, data.expiry_date,
        data.updated_date, data.name_servers,
        data.page_language, data.page_title,
        data.threat_type, data.target_brand, data.threat_tags,
        data.source_feed, data.source_id, data.last_seen,
        data.notes
    ))

    con.commit()
    cur.close()
    con.close()


def insert_enriched_data_batch(
        enriched_db_path: Path,
        data_list: List[EnrichmentData]
):
    """Batch insert enriched data with ULTRA performance optimizations."""
    if not data_list:
        return
    
    con = sqlite3.connect(str(enriched_db_path))
    
    # ULTRA PERFORMANCE: Enable WAL mode and aggressive pragmas
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")  # Faster than FULL
    con.execute("PRAGMA cache_size=100000")  # 100MB cache
    con.execute("PRAGMA temp_store=MEMORY")  # Use memory for temp
    
    cur = con.cursor()
    
    # Prepare all records
    records = []
    for data in data_list:
        records.append((
            data.url, data.domain, data.online, data.http_status_code,
            data.ip_address, data.cidr_block, data.asn, data.asn_name,
            data.isp, data.country, data.country_name, data.region,
            data.city, data.latitude, data.longitude,
            data.ssl_enabled, data.cert_issuer, data.cert_subject,
            data.cert_valid_from, data.cert_valid_to, data.cert_serial,
            data.tld, data.registrar, data.creation_date, data.expiry_date,
            data.updated_date, data.name_servers,
            data.page_language, data.page_title,
            data.threat_type, data.target_brand, data.threat_tags,
            data.source_feed, data.source_id, data.last_seen,
            data.notes
        ))
    
    # Batch insert
    cur.executemany("""
        INSERT OR REPLACE INTO enriched_threats (
            url, domain, online, http_status_code,
            ip_address, cidr_block, asn, asn_name, isp,
            country, country_name, region, city, latitude, longitude,
            ssl_enabled, cert_issuer, cert_subject,
            cert_valid_from, cert_valid_to, cert_serial,
            tld, registrar, creation_date, expiry_date,
            updated_date, name_servers,
            page_language, page_title,
            threat_type, target_brand, threat_tags,
            source_feed, source_id, last_seen, last_checked,
            notes, updated_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, datetime('now'), ?, datetime('now')
        )
    """, records)
    
    con.commit()
    
    # Calculate risk scores for the newly inserted records
    if records:
        try:
            # Get URLs from the records to update their risk scores
            urls = [record[0] for record in records]  # URL is first field
            url_placeholders = ','.join('?' * len(urls))
            
            # Update risk scores for just the inserted records
            con.execute(f"""
                UPDATE enriched_threats 
                SET risk_score = (
                    -- Liveness Score (0-35 pts)
                    CASE 
                        WHEN http_status_code IN (200, 301, 302, 307, 308) THEN 35
                        WHEN http_status_code IN (401, 403, 405, 429, 451) THEN 28
                        WHEN http_status_code >= 500 AND http_status_code < 600 THEN 20
                        WHEN http_status_code IN (404, 410) THEN 12
                        WHEN http_status_code IS NOT NULL THEN 10
                        WHEN online = 'yes' THEN 20
                        WHEN online = 'no' OR online IS NULL THEN 10
                        ELSE 10
                    END
                    +
                    -- Recency Score (0-25 pts)
                    CASE 
                        WHEN last_seen IS NULL THEN 5
                        WHEN julianday('now') - julianday(last_seen) <= 3 THEN 25
                        WHEN julianday('now') - julianday(last_seen) <= 7 THEN 20
                        WHEN julianday('now') - julianday(last_seen) <= 14 THEN 15
                        WHEN julianday('now') - julianday(last_seen) <= 30 THEN 10
                        ELSE 5
                    END
                    +
                    -- Domain Age Score (0-20 pts)
                    CASE 
                        WHEN creation_date IS NULL THEN 8
                        WHEN julianday('now') - julianday(creation_date) <= 7 THEN 20
                        WHEN julianday('now') - julianday(creation_date) <= 30 THEN 15
                        WHEN julianday('now') - julianday(creation_date) <= 90 THEN 10
                        ELSE 5
                    END
                    +
                    -- TLD/Platform Score (0-10 pts)
                    CASE
                        WHEN LOWER(tld) IN ('zip', 'mov', 'top', 'cc', 'icu', 'xyz', 'click', 'info') THEN 
                            CASE 
                                WHEN LOWER(url) LIKE '%.vercel.app%' OR LOWER(url) LIKE '%.web.app%' OR 
                                     LOWER(url) LIKE '%.github.io%' OR LOWER(url) LIKE '%.cprapid.com%' OR
                                     LOWER(url) LIKE '%.pages.dev%' OR LOWER(url) LIKE '%.netlify.app%' OR
                                     LOWER(url) LIKE '%.render.com%' OR LOWER(url) LIKE '%.fly.dev%' THEN 10
                                ELSE 10
                            END
                        WHEN LOWER(tld) IN ('com', 'net', 'org') THEN
                            CASE 
                                WHEN LOWER(url) LIKE '%.vercel.app%' OR LOWER(url) LIKE '%.web.app%' OR 
                                     LOWER(url) LIKE '%.github.io%' OR LOWER(url) LIKE '%.cprapid.com%' OR
                                     LOWER(url) LIKE '%.pages.dev%' OR LOWER(url) LIKE '%.netlify.app%' OR
                                     LOWER(url) LIKE '%.render.com%' OR LOWER(url) LIKE '%.fly.dev%' THEN 8
                                ELSE 5
                            END
                        ELSE 
                            CASE 
                                WHEN LOWER(url) LIKE '%.vercel.app%' OR LOWER(url) LIKE '%.web.app%' OR 
                                     LOWER(url) LIKE '%.github.io%' OR LOWER(url) LIKE '%.cprapid.com%' OR
                                     LOWER(url) LIKE '%.pages.dev%' OR LOWER(url) LIKE '%.netlify.app%' OR
                                     LOWER(url) LIKE '%.render.com%' OR LOWER(url) LIKE '%.fly.dev%' THEN 10
                                ELSE 7
                            END
                    END
                    +
                    -- URL Keywords Score (0-3 pts; reduced for benign-mail false positives)
                    CASE 
                        WHEN LOWER(url) LIKE '%login%' OR LOWER(url) LIKE '%verify%' OR LOWER(url) LIKE '%secure%' OR
                             LOWER(url) LIKE '%update%' OR LOWER(url) LIKE '%invoice%' OR LOWER(url) LIKE '%mfa%' OR
                             LOWER(url) LIKE '%password%' OR LOWER(url) LIKE '%wallet%' OR LOWER(url) LIKE '%bank%' OR
                             LOWER(url) LIKE '%microsoft%' OR LOWER(url) LIKE '%office365%' OR LOWER(url) LIKE '%att%' THEN 3
                        ELSE 0
                    END
                )
                WHERE url IN ({url_placeholders})
            """, urls)
            con.commit()
        except Exception as e:
            print(f"Warning: Could not calculate risk scores for batch: {e}")
    
    cur.close()
    con.close()


def check_already_enriched(enriched_db_path: Path, url: str) -> bool:
    """Check if URL is already enriched."""
    con = sqlite3.connect(str(enriched_db_path))
    cur = con.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM enriched_threats WHERE url = ?", (url,))
    count = cur.fetchone()[0]
    cur.close()
    con.close()
    return count > 0


def check_already_enriched_batch(
        enriched_db_path: Path,
        urls: List[str]
) -> Dict[str, bool]:
    """Batch check if URLs are already enriched (optimized for speed)."""
    if not urls:
        return {}
    
    con = sqlite3.connect(str(enriched_db_path))
    
    # Performance optimizations
    con.execute("PRAGMA cache_size=50000")
    con.execute("PRAGMA temp_store=MEMORY")
    
    cur = con.cursor()
    
    # Use IN clause for batch query
    placeholders = ','.join('?' * len(urls))
    cur.execute(
        f"SELECT url FROM enriched_threats WHERE url IN ({placeholders})",
        urls
    )
    
    enriched_urls = {row[0] for row in cur.fetchall()}
    cur.close()
    con.close()
    
    # Return dict of url -> is_enriched
    return {url: (url in enriched_urls) for url in urls}


async def process_batch_async(
        batch: List[Tuple[str, str, Optional[str], Dict[str, Any]]],
        enriched_db: Path,
        skip_existing: bool,
        executor: ThreadPoolExecutor,
        enable_whois: bool = True,
        enable_ipwhois: bool = True,
        enable_page_content: bool = True,
        stats: Optional[Dict[str, int]] = None
) -> Tuple[int, int, int]:
    """
    Process a batch of URLs concurrently.
    
    Returns: (processed, skipped, failed) counts
    """
    processed = 0
    skipped = 0
    failed = 0
    
    enriched_data_list = []
    
    # Batch check for existing URLs (MUCH faster than one-by-one)
    enriched_status = {}
    if skip_existing:
        all_urls = [url for url, _, _, _ in batch]
        loop = asyncio.get_event_loop()
        enriched_status = await loop.run_in_executor(
            executor, check_already_enriched_batch, enriched_db, all_urls
        )
    
    # Create tasks for all URLs in batch
    tasks = []
    urls_to_process = []
    
    for url, source_feed, source_id, existing_data in batch:
        # Skip if already enriched (use batch result)
        if skip_existing and enriched_status.get(url, False):
            skipped += 1
            continue
        
        urls_to_process.append((url, source_feed, source_id))
        task = enrich_url_async(
            url, source_feed, source_id, existing_data, executor,
            enable_whois, enable_ipwhois, enable_page_content
        )
        tasks.append(task)
    
    # Process all URLs concurrently
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            url, source_feed, source_id = urls_to_process[i]
            
            if isinstance(result, Exception):
                failed += 1
            else:
                enriched_data_list.append(result)
                processed += 1
                
                # Track statistics about null values
                if stats is not None:
                    if result.ip_address:
                        stats['has_ip'] += 1
                    else:
                        stats['missing_ip'] += 1
                    
                    if result.asn:
                        stats['has_asn'] += 1
                    else:
                        stats['missing_asn'] += 1
                        if result.ip_address:
                            stats['missing_asn_with_ip'] += 1
                    
                    if result.isp:
                        stats['has_isp'] += 1
                    else:
                        stats['missing_isp'] += 1
                        if result.ip_address:
                            stats['missing_isp_with_ip'] += 1
                    
                    if result.country:
                        stats['has_country'] += 1
                    else:
                        stats['missing_country'] += 1
    
    # Batch insert all results
    if enriched_data_list:
        insert_enriched_data_batch(enriched_db, enriched_data_list)
    
    return processed, skipped, failed


async def process_all_async(
        raw_urls: List[Tuple[str, str, Optional[str], Dict[str, Any]]],
        enriched_db: Path,
        skip_existing: bool,
        max_concurrent: int = MAX_CONCURRENT_URLS,
        max_workers: int = MAX_WORKER_THREADS,
        enable_whois: bool = True,
        enable_ipwhois: bool = True,
        enable_page_content: bool = True,
        debug_enabled: bool = False
) -> Tuple[int, int, int, Dict[str, int]]:
    """
    Process all URLs with concurrent batching.
    
    Returns: (total_processed, total_skipped, total_failed, stats)
    """
    total_processed = 0
    total_skipped = 0
    total_failed = 0
    
    # Statistics tracking for null values
    stats = {
        'has_ip': 0,
        'missing_ip': 0,
        'has_asn': 0,
        'missing_asn': 0,
        'missing_asn_with_ip': 0,
        'has_isp': 0,
        'missing_isp': 0,
        'missing_isp_with_ip': 0,
        'has_country': 0,
        'missing_country': 0,
    }
    
    # Create thread pool for blocking operations
    executor = ThreadPoolExecutor(max_workers=max_workers)
    
    try:
        # Process in batches (silent processing for max speed)
        total_batches = (len(raw_urls) + max_concurrent - 1) // max_concurrent
        for i in range(0, len(raw_urls), max_concurrent):
            batch = raw_urls[i:i + max_concurrent]
            batch_num = (i // max_concurrent) + 1
            
            # Show progress every 10 batches or on first/last batch
            if batch_num == 1 or batch_num == total_batches or batch_num % 10 == 0:
                print(f"Processing batch {batch_num}/{total_batches}...", flush=True)
            
            processed, skipped, failed = await process_batch_async(
                batch, enriched_db, skip_existing, executor,
                enable_whois, enable_ipwhois, enable_page_content, stats
            )
            
            total_processed += processed
            total_skipped += skipped
            total_failed += failed
    
    finally:
        executor.shutdown(wait=True)
    
    return total_processed, total_skipped, total_failed, stats


def main():
    """Main enrichment pipeline."""
    parser = argparse.ArgumentParser(
        description="Enrich threat feed data with WHOIS, GeoIP, etc."
    )
    parser.add_argument(
        '--raw-db',
        default=str(RAW_DB_PATH),
        help='Path to raw database'
    )
    parser.add_argument(
        '--enriched-db',
        default=str(ENRICHED_DB_PATH),
        help='Path to enriched database'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Limit number of URLs to process'
    )
    parser.add_argument(
        '--skip-existing',
        action='store_true',
        help='Skip URLs already in enriched database'
    )
    parser.add_argument(
        '--source',
        choices=['openphish', 'phishtank', 'urlhaus', 'tranco_ml_benign'],
        help='Process only specific source feed'
    )
    parser.add_argument(
        '--legacy',
        action='store_true',
        help='Use legacy synchronous processing (slower but simpler)'
    )
    parser.add_argument(
        '--concurrency',
        type=int,
        default=MAX_CONCURRENT_URLS,
        help=f'Number of URLs to process concurrently (default: {MAX_CONCURRENT_URLS})'
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=MAX_WORKER_THREADS,
        help=f'Thread pool size for blocking operations (default: {MAX_WORKER_THREADS})'
    )
    parser.add_argument(
        '--disable-whois',
        action='store_true',
        help='Disable WHOIS lookups for speed (loses registrar data)'
    )
    parser.add_argument(
        '--disable-ipwhois',
        action='store_true',
        help='Disable IPWhois lookups for speed (loses CIDR data)'
    )
    parser.add_argument(
        '--disable-page-content',
        action='store_true',
        help='Disable page content fetching for speed (loses title/language)'
    )
    parser.add_argument(
        '--fast-ml',
        action='store_true',
        help=(
            'Bulk-ML shortcut: same as --disable-whois --disable-ipwhois '
            '--disable-page-content. Per URL, wall time is dominated by the '
            'slowest parallel step (usually WHOIS port 43, then full GET page fetch, '
            'then RDAP/IPWhois); this keeps DNS/SSL/GeoIP-MMDB/HTTP HEAD-style probes. '
            'Does not apply to --legacy (async mode only).'
        ),
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging to file (enrichment_debug.log)'
    )
    args = parser.parse_args()

    if args.fast_ml:
        args.disable_whois = True
        args.disable_ipwhois = True
        args.disable_page_content = True

    raw_db = Path(args.raw_db)
    enriched_db = Path(args.enriched_db)

    if not raw_db.exists():
        logger.error(f"Raw database not found: {raw_db}")
        return 1

    if not enriched_db.exists():
        logger.error(f"Enriched database not found: {enriched_db}")
        logger.info("Run 'python -m app.database.db' to create it")
        return 1

    # Configure debug logging if --debug flag is set
    if args.debug:
        debug_logger.setLevel(logging.DEBUG)
        debug_logger.handlers.clear()
        debug_handler = logging.FileHandler(DB_DIR / 'enrichment_debug.log')
        debug_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        debug_logger.addHandler(debug_handler)
        logger.info("Debug logging enabled -> enrichment_debug.log")

    # Warn about missing optional dependencies
    if not WHOIS_AVAILABLE:
        logger.warning(
            "WHOIS disabled for %s — install: %s -m pip install python-whois",
            sys.executable,
            sys.executable,
        )
    if not GEOIP_AVAILABLE:
        logger.warning("GeoIP lookups disabled - install geoip2")
        logger.info(
            "Download GeoLite2 databases from "
            "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
        )
    if not IPWHOIS_AVAILABLE:
        logger.warning(
            "IPWhois disabled for %s — install: %s -m pip install ipwhois",
            sys.executable,
            sys.executable,
        )
    if not REQUESTS_AVAILABLE:
        logger.warning("HTTP checks disabled - install requests")

    # Get raw data
    logger.info("Fetching URLs from raw database...")
    raw_urls = get_raw_data(raw_db)

    # Filter by source if specified
    if args.source:
        raw_urls = [
            r for r in raw_urls if r[1] == args.source
        ]
        logger.info(f"Filtered to {len(raw_urls)} URLs from {args.source}")

    # Apply limit
    if args.limit:
        raw_urls = raw_urls[:args.limit]
        logger.info(f"Limited to {args.limit} URLs")

    # Use concurrency settings from CLI args (without modifying globals)
    max_concurrent = args.concurrency if args.concurrency else MAX_CONCURRENT_URLS
    max_workers = args.workers if args.workers else MAX_WORKER_THREADS

    # Choose processing mode
    if args.legacy:
        # Legacy synchronous processing
        logger.info(f"\n{'='*60}")
        logger.info("Starting LEGACY synchronous enrichment pipeline...")
        logger.warning("Using legacy mode - consider async mode for better performance")
        
        processed = 0
        skipped = 0
        failed = 0
        
        try:
            for url, source_feed, source_id, existing_data in raw_urls:
                try:
                    if args.skip_existing and check_already_enriched(enriched_db, url):
                        logger.info(f"Skipping already enriched: {url}")
                        skipped += 1
                        continue

                    logger.info(f"\n{'='*60}")
                    logger.info(f"Enriching [{processed+1}/{len(raw_urls)}]: {url}")
                    logger.info(f"Source: {source_feed}")

                    enriched = enrich_url(url, source_feed, source_id, existing_data)
                    insert_enriched_data(enriched_db, enriched)

                    processed += 1
                    logger.info(f"✓ Successfully enriched: {url}")
                    time.sleep(0.5)

                except Exception as e:
                    logger.error(f"✗ Failed to enrich {url}: {e}", exc_info=True)
                    failed += 1
                    
        except KeyboardInterrupt:
            logger.info("\nInterrupted by user")
    else:
        # Modern async batch processing
        start_time = time.time()
        print(f"\n{'='*60}")
        print("Starting ULTRA-FAST async enrichment pipeline...")
        print(f"Concurrency: {max_concurrent} URLs per batch")
        print(f"Thread pool: {max_workers} workers")
        print(f"Batch insert: {BATCH_INSERT_SIZE} records")
        print(f"Total URLs: {len(raw_urls)}")
        if args.fast_ml:
            print(
                "Mode: --fast-ml (skips WHOIS, IPWhois RDAP, full page GET — "
                "largest wall-clock wins removed; GeoIP/SSL/online still run)"
            )

        # Show what's enabled (CLI flags) vs actually available (optional deps)
        whois_flag = not args.disable_whois
        ipwhois_flag = not args.disable_ipwhois
        page_flag = not args.disable_page_content
        print("\nFeatures (flag vs runtime):")
        if whois_flag and WHOIS_AVAILABLE:
            whois_status = "✓ active (python-whois)"
        elif not whois_flag:
            whois_status = "✗ off (--disable-whois)"
        else:
            whois_status = "✗ unavailable (pip install python-whois)"
        if ipwhois_flag and IPWHOIS_AVAILABLE:
            ipwhois_status = "✓ active (ipwhois)"
        elif not ipwhois_flag:
            ipwhois_status = "✗ off (--disable-ipwhois)"
        else:
            ipwhois_status = "✗ unavailable (pip install ipwhois)"
        page_status = "✓ enabled" if page_flag else "✗ disabled (--disable-page-content)"
        print(f"   • WHOIS:        {whois_status}")
        print(f"   • IPWhois:      {ipwhois_status}")
        print(f"   • Page content: {page_status}")
        if (whois_flag and not WHOIS_AVAILABLE) or (ipwhois_flag and not IPWHOIS_AVAILABLE):
            print(f"\nThese use the Python that is running enrich:\n  {sys.executable}")
            print("Install into that environment (examples):")
            print(f"  {sys.executable} -m pip install python-whois ipwhois")
            if _REQUIREMENTS_FILE.is_file():
                print(
                    f"  {sys.executable} -m pip install -r {_REQUIREMENTS_FILE}"
                )
            print(
                "If pip refuses (e.g. Arch 'externally-managed-environment'), create a venv:\n"
                f"  python3 -m venv .venv && .venv/bin/python -m pip install -r {_REQUIREMENTS_FILE}\n"
                "Then run enrich with, for example:\n"
                "  PYTHON=.venv/bin/python python -m app.database.enrich --skip-existing"
            )
        print(f"{'='*60}\n")
        
        stats = {}
        try:
            processed, skipped, failed, stats = asyncio.run(
                process_all_async(
                    raw_urls, enriched_db, args.skip_existing,
                    max_concurrent, max_workers,
                    not args.disable_whois,
                    not args.disable_ipwhois,
                    not args.disable_page_content,
                    args.debug
                )
            )
        except KeyboardInterrupt:
            print("\nInterrupted by user")
            processed = skipped = failed = 0
            stats = {}

    elapsed = time.time() - start_time if 'start_time' in locals() else 0
    
    # Final summary
    print(f"\n{'='*60}")
    print("Enrichment pipeline completed!")
    print(f"{'='*60}")
    print("Results:")
    print(f"   • Processed:  {processed:,}")
    print(f"   • Skipped:    {skipped:,}")
    print(f"   • Failed:     {failed:,}")
    print(f"   • Total URLs: {len(raw_urls):,}")
    if elapsed > 0:
        print("\nPerformance:")
        print(f"   • Time:       {elapsed:.1f}s")
        print(f"   • Speed:      {len(raw_urls)/elapsed:.1f} URLs/sec")
        if processed > 0:
            print(f"   • Avg/URL:    {elapsed/processed:.2f}s")
    
    # Data quality statistics
    if stats and processed > 0:
        print("\nData Quality:")
        print(f"   • IP Address:     {stats['has_ip']:,} / {processed:,} "
              f"({100*stats['has_ip']/processed:.1f}%)")
        print(f"   • ASN:            {stats['has_asn']:,} / {processed:,} "
              f"({100*stats['has_asn']/processed:.1f}%)")
        if stats['missing_asn_with_ip'] > 0:
            print(f"     ⚠ Missing ASN despite having IP: "
                  f"{stats['missing_asn_with_ip']:,}")
        print(f"   • ISP:            {stats['has_isp']:,} / {processed:,} "
              f"({100*stats['has_isp']/processed:.1f}%)")
        if stats['missing_isp_with_ip'] > 0:
            print(f"     ⚠ Missing ISP despite having IP: "
                  f"{stats['missing_isp_with_ip']:,}")
        print(f"   • Country:        {stats['has_country']:,} / {processed:,} "
              f"({100*stats['has_country']/processed:.1f}%)")
        
        # Write detailed stats to debug log (only if debug enabled)
        if args.debug:
            debug_logger.info(f"=== Enrichment Session Summary ===")
            debug_logger.info(f"Processed: {processed}, Skipped: {skipped}, "
                             f"Failed: {failed}")
            debug_logger.info(f"Data completeness: {stats}")
            debug_logger.info(f"Check enrichment_debug.log for detailed traces")
            
            print(f"\n📋 Detailed debugging info written to: "
                  f"{DB_DIR / 'enrichment_debug.log'}")
    
    # Calculate risk scores for all threats after enrichment
    if processed > 0:
        print(f"\n🎯 Calculating risk scores for enriched threats...")
        from .db import calculate_risk_scores
        try:
            calculate_risk_scores(Path(args.enriched_db))
        except Exception as e:
            print(f"⚠️ Warning: Failed to calculate risk scores: {e}")
    
    print(f"{'='*60}\n")
    
    return 0


if __name__ == "__main__":
    exit(main())
