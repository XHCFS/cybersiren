package url

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

// Feature order matches Python training column order exactly.
// F04 (has_ip_address) and F24 (double_slash_in_path) are pruned per ML-SPEC-v1.1 §5.
//
// Index → feature name:
//
//	 0  url_length           F01
//	 1  num_dots             F02
//	 2  num_subdomains       F03
//	 3  num_hyphens_url      F05
//	 4  num_hyphens_hostname F06
//	 5  https_flag           F07
//	 6  entropy_url          F08
//	 7  num_numeric_chars    F09
//	 8  num_sensitive_words  F10
//	 9  hostname_length      F11
//	10  path_length          F12
//	11  url_char_prob        F13
//	12  char_continuation_rate F14
//	13  tld_legit_prob       F15
//	14  entropy_domain       F16
//	15  num_query_params     F17
//	16  num_special_chars    F18
//	17  at_symbol_present    F19
//	18  pct_numeric_chars    F20
//	19  suspicious_file_ext  F21
//	20  path_depth           F22
//	21  num_underscores      F23
//	22  query_length         F25
//	23  has_fragment         F26
//	24  has_repeated_digits  F27
//	25  avg_subdomain_length F28
//	26  tld_length           F29
//	27  token_count          F30

// FeatureCount is the number of active features returned by ExtractFeatures.
const FeatureCount = 28

// Static lookup tables (loaded once at process start).
var (
	sensitiveWords = []string{
		"secure", "account", "webscr", "login", "ebayisapi", "signin",
		"banking", "confirm", "update", "verify", "password", "suspend",
		"paypal", "authenticate", "wallet", "credential",
	}

	suspiciousExts = map[string]bool{
		".exe": true, ".zip": true, ".rar": true, ".scr": true,
		".bat": true, ".cmd": true, ".msi": true, ".dll": true,
		".vbs": true, ".js": true, ".jar": true, ".ps1": true,
		".wsf": true, ".lnk": true, ".7z": true, ".cab": true,
	}

	// charProbTable maps each lowercase alphanumeric character to its probability
	// in legitimate Cisco Umbrella top-1M URLs. Used for F13 url_char_prob.
	charProbTable = map[rune]float64{
		'0': 0.0078637338, '1': 0.0101679180, '2': 0.0074502294,
		'3': 0.0055957308, '4': 0.0051794522, '5': 0.0056410549,
		'6': 0.0042180731, '7': 0.0037996455, '8': 0.0035634913,
		'9': 0.0034425618,
		'a': 0.0589765190, 'b': 0.0161821154, 'c': 0.0611543036,
		'd': 0.0312923155, 'e': 0.0691772970, 'f': 0.0130443973,
		'g': 0.0212382157, 'h': 0.0523380601, 'i': 0.0441889406,
		'j': 0.0033305019, 'k': 0.0105264083, 'l': 0.0302732653,
		'm': 0.0474257857, 'n': 0.0475272179, 'o': 0.0740223276,
		'p': 0.0671214968, 'q': 0.0031705390, 'r': 0.0420973890,
		's': 0.0487208050, 't': 0.1232198563, 'u': 0.0242928657,
		'v': 0.0134484462, 'w': 0.0179498731, 'x': 0.0070832213,
		'y': 0.0098243925, 'z': 0.0054515532,
	}

	// tldLegitProb maps each TLD suffix to its frequency in legitimate Cisco
	// Umbrella top-1M URLs. Used for F15 tld_legit_prob.
	tldLegitProb = map[string]float64{
		"abb": 0.0000050000, "abbott": 0.0000260000, "abbvie": 0.0000010000,
		"abc": 0.0000010000, "abudhabi": 0.0000030000, "ac": 0.0000460000,
		"ac.in": 0.0000350000, "ac.uk": 0.0006310000, "academy": 0.0000160000,
		"accountants": 0.0000020000, "actor": 0.0000020000, "ad": 0.0000200000,
		"ads": 0.0000010000, "adult": 0.0000030000, "ae": 0.0001810000,
		"aero": 0.0000740000, "af": 0.0000030000, "africa": 0.0000130000,
		"ag": 0.0000660000, "agency": 0.0000240000, "ai": 0.0036560000,
		"al": 0.0000130000, "am": 0.0000440000, "amex": 0.0000020000,
		"analytics": 0.0000020000, "android": 0.0000100000, "ao": 0.0000100000,
		"app": 0.0042310000, "apple": 0.0000160000, "ar": 0.0001070000,
		"army": 0.0000100000, "arpa": 0.0000440000, "as": 0.0000220000,
		"asia": 0.0002600000, "at": 0.0012340000, "au": 0.0003080000,
		"auction": 0.0000080000, "audi": 0.0000620000, "audio": 0.0000390000,
		"auto": 0.0000320000, "autos": 0.0001970000, "aw": 0.0000010000,
		"aws": 0.0006830000, "ax": 0.0000090000, "az": 0.0000290000,
		"azure": 0.0000020000, "ba": 0.0000250000, "baby": 0.0000390000,
		"band": 0.0000020000, "bank": 0.0000740000, "bar": 0.0000320000,
		"barcelona": 0.0000010000, "barclaycard": 0.0000050000, "barclays": 0.0000070000,
		"bargains": 0.0000020000, "basketball": 0.0000040000, "bauhaus": 0.0000060000,
		"bayern": 0.0000040000, "bbva": 0.0000020000, "bd": 0.0000660000,
		"be": 0.0026150000, "beauty": 0.0000500000, "beer": 0.0000160000,
		"berlin": 0.0000140000, "best": 0.0000340000, "bet": 0.0000720000,
		"bf": 0.0000040000, "bg": 0.0001680000, "bh": 0.0000110000,
		"bi": 0.0000190000, "bid": 0.0001060000, "bike": 0.0000160000,
		"bingo": 0.0000090000, "bio": 0.0000350000, "biz": 0.0010210000,
		"bj": 0.0000020000, "black": 0.0000060000, "blog": 0.0001190000,
		"blue": 0.0000380000, "bm": 0.0000400000, "bmw": 0.0001180000,
		"bn": 0.0000090000, "bnpparibas": 0.0000160000, "bo": 0.0000160000,
		"boats": 0.0000690000, "bond": 0.0000470000, "boo": 0.0000070000,
		"boston": 0.0000010000, "bot": 0.0001180000, "boutique": 0.0000030000,
		"box": 0.0000760000, "br": 0.0004570000, "bradesco": 0.0000020000,
		"brother": 0.0000010000, "brussels": 0.0000100000, "bs": 0.0000050000,
		"bt": 0.0000040000, "build": 0.0000550000, "business": 0.0000190000,
		"buzz": 0.0001700000, "bw": 0.0000070000, "by": 0.0001520000,
		"bz": 0.0000930000, "bzh": 0.0000030000, "ca": 0.0017050000,
		"cab": 0.0000050000, "cafe": 0.0000410000, "camera": 0.0000090000,
		"camp": 0.0000040000, "canon": 0.0000170000, "capital": 0.0000050000,
		"car": 0.0000040000, "cards": 0.0000150000, "care": 0.0000670000,
		"career": 0.0000010000, "careers": 0.0000070000, "cars": 0.0000060000,
		"casa": 0.0000220000, "cash": 0.0000160000, "casino": 0.0000030000,
		"cat": 0.0000780000, "catering": 0.0000010000, "cc": 0.0035000000,
		"cd": 0.0000060000, "center": 0.0000390000, "ceo": 0.0000010000,
		"cf": 0.0000610000, "cfd": 0.0003630000, "cg": 0.0000020000,
		"ch": 0.0014880000, "channel": 0.0000050000, "chat": 0.0002360000,
		"christmas": 0.0000020000, "chrome": 0.0000060000, "church": 0.0000130000,
		"ci": 0.0000130000, "cisco": 0.0000060000, "citic": 0.0000030000,
		"city": 0.0000210000, "ck": 0.0000020000, "cl": 0.0003680000,
		"cleaning": 0.0000010000, "click": 0.0003520000, "clinic": 0.0000010000,
		"clothing": 0.0000040000, "cloud": 0.0059410000, "club": 0.0004860000,
		"clubmed": 0.0000060000, "cm": 0.0000210000, "cn": 0.0062960000,
		"co": 0.0054280000, "co.id": 0.0010830000, "co.il": 0.0002680000,
		"co.in": 0.0001290000, "co.jp": 0.0007310000, "co.kr": 0.0003560000,
		"co.nz": 0.0004320000, "co.uk": 0.0104740000, "co.ve": 0.0000050000,
		"co.za": 0.0003410000, "coach": 0.0000070000, "codes": 0.0000250000,
		"coffee": 0.0000070000, "college": 0.0000020000, "cologne": 0.0000010000,
		"com": 0.6168390000, "com.ar": 0.0001520000, "com.au": 0.0011750000,
		"com.br": 0.0015840000, "com.cn": 0.0017940000, "com.hk": 0.0001860000,
		"com.mx": 0.0009410000, "com.my": 0.0004310000, "com.ng": 0.0000280000,
		"com.pe": 0.0000740000, "com.ph": 0.0002490000, "com.pk": 0.0000430000,
		"com.sg": 0.0001980000, "com.tw": 0.0003890000, "community": 0.0000180000,
		"company": 0.0000110000, "computer": 0.0000050000, "construction": 0.0000010000,
		"consulting": 0.0000020000, "contractors": 0.0000020000, "cool": 0.0000650000,
		"coop": 0.0000640000, "courses": 0.0000020000, "cr": 0.0002700000,
		"crown": 0.0000010000, "cu": 0.0000160000, "cv": 0.0000230000,
		"cw": 0.0000030000, "cx": 0.0000590000, "cy": 0.0001230000,
		"cymru": 0.0000090000, "cyou": 0.0004330000, "cz": 0.0010020000,
		"dad": 0.0000030000, "date": 0.0000010000, "dating": 0.0000140000,
		"day": 0.0000130000, "de": 0.0085920000, "dealer": 0.0000020000,
		"deals": 0.0000060000, "delivery": 0.0001200000, "deloitte": 0.0000020000,
		"dental": 0.0000100000, "desi": 0.0000820000, "design": 0.0000460000,
		"dev": 0.0029040000, "dhl": 0.0000070000, "digital": 0.0003000000,
		"direct": 0.0000290000, "directory": 0.0000050000, "diy": 0.0000030000,
		"dj": 0.0000020000, "dk": 0.0004520000, "dm": 0.0000120000,
		"do": 0.0001810000, "dog": 0.0000030000, "domains": 0.0000120000,
		"download": 0.0000270000, "dz": 0.0000350000, "earth": 0.0000170000,
		"ec": 0.0001000000, "edeka": 0.0000090000, "edu": 0.0051240000,
		"education": 0.0000290000, "ee": 0.0001720000, "eg": 0.0000370000,
		"email": 0.0001450000, "energy": 0.0000600000, "engineering": 0.0000330000,
		"enterprises": 0.0000010000, "equipment": 0.0000050000, "es": 0.0012500000,
		"estate": 0.0000020000, "et": 0.0000100000, "eu": 0.0026660000,
		"eus": 0.0000190000, "events": 0.0000650000, "exchange": 0.0000180000,
		"expert": 0.0000190000, "exposed": 0.0000010000, "express": 0.0000120000,
		"family": 0.0000070000, "fan": 0.0000290000, "fans": 0.0000180000,
		"farm": 0.0000250000, "fashion": 0.0000250000, "fi": 0.0035010000,
		"film": 0.0000120000, "finance": 0.0000200000, "financial": 0.0000020000,
		"fish": 0.0000050000, "fit": 0.0000720000, "fitness": 0.0000100000,
		"fj": 0.0000020000, "flickr": 0.0000010000, "flir": 0.0000020000,
		"fm": 0.0002680000, "fo": 0.0000090000, "foo": 0.0000030000,
		"football": 0.0000020000, "ford": 0.0000010000, "forsale": 0.0000040000,
		"forum": 0.0000110000, "foundation": 0.0000090000, "fox": 0.0000360000,
		"fr": 0.0021530000, "free": 0.0000050000, "ftr": 0.0000010000,
		"fun": 0.0004800000, "fund": 0.0000020000, "futbol": 0.0000030000,
		"fyi": 0.0000270000, "ga": 0.0000510000, "gal": 0.0000110000,
		"gallery": 0.0000050000, "game": 0.0000450000, "games": 0.0003410000,
		"garden": 0.0000070000, "gd": 0.0000170000, "gdn": 0.0000080000,
		"ge": 0.0000570000, "gg": 0.0004480000, "gh": 0.0000160000,
		"gi": 0.0000020000, "gift": 0.0000020000, "gifts": 0.0000010000,
		"gives": 0.0000010000, "gl": 0.0000330000, "glass": 0.0000040000,
		"gle": 0.0000030000, "global": 0.0001710000, "globo": 0.0000280000,
		"gm": 0.0000040000, "gmbh": 0.0000030000, "godaddy": 0.0000010000,
		"gold": 0.0000100000, "golf": 0.0000120000, "goog": 0.0007030000,
		"google": 0.0000610000, "gov": 0.0042150000, "gov.uk": 0.0007990000,
		"gp": 0.0000050000, "gq": 0.0000320000, "gr": 0.0008550000,
		"graphics": 0.0000020000, "gratis": 0.0000030000, "green": 0.0000080000,
		"group": 0.0000730000, "gs": 0.0000320000, "gt": 0.0001690000,
		"gucci": 0.0000020000, "guide": 0.0000110000, "guru": 0.0000470000,
		"gw": 0.0000060000, "gy": 0.0000210000, "hair": 0.0000210000,
		"hamburg": 0.0000050000, "haus": 0.0000050000, "hbo": 0.0000010000,
		"health": 0.0001230000, "healthcare": 0.0000060000, "help": 0.0001120000,
		"here": 0.0000010000, "hk": 0.0001750000, "hm": 0.0000010000,
		"hn": 0.0000730000, "hockey": 0.0000040000, "holdings": 0.0000020000,
		"homes": 0.0000780000, "honda": 0.0000010000, "horse": 0.0000040000,
		"host": 0.0001200000, "hosting": 0.0000220000, "hot": 0.0000030000,
		"house": 0.0000090000, "how": 0.0000050000, "hr": 0.0001580000,
		"hsbc": 0.0000090000, "ht": 0.0000100000, "hu": 0.0008690000,
		"ice": 0.0000010000, "icu": 0.0003960000, "id": 0.0018050000,
		"ie": 0.0004510000, "ifm": 0.0000020000, "il": 0.0000960000,
		"im": 0.0002020000, "immo": 0.0000040000, "in": 0.0013240000,
		"industries": 0.0000140000, "info": 0.0018470000, "ing": 0.0000070000,
		"ink": 0.0001750000, "institute": 0.0000010000, "int": 0.0001650000,
		"international": 0.0000100000, "io": 0.0228730000, "iq": 0.0000090000,
		"ir": 0.0006940000, "is": 0.0001510000, "ist": 0.0000080000,
		"istanbul": 0.0000020000, "it": 0.0018730000, "jcb": 0.0000020000,
		"je": 0.0000090000, "jetzt": 0.0000030000, "jewelry": 0.0000010000,
		"jm": 0.0000110000, "jo": 0.0000100000, "jobs": 0.0000410000,
		"jp": 0.0017990000, "ke": 0.0000710000, "kg": 0.0000240000,
		"kh": 0.0000350000, "ki": 0.0000110000, "kim": 0.0000060000,
		"kindle": 0.0000010000, "kitchen": 0.0000060000, "kiwi": 0.0000030000,
		"kn": 0.0000030000, "komatsu": 0.0000060000, "kr": 0.0001880000,
		"krd": 0.0000030000, "kw": 0.0000100000, "ky": 0.0000070000,
		"kz": 0.0002090000, "la": 0.0003920000, "land": 0.0000290000,
		"landrover": 0.0000010000, "lat": 0.0000960000, "law": 0.0000140000,
		"lawyer": 0.0000010000, "lb": 0.0000100000, "lc": 0.0000040000,
		"leclerc": 0.0000040000, "legal": 0.0000140000, "lgbt": 0.0000040000,
		"li": 0.0000840000, "lidl": 0.0000050000, "life": 0.0002530000,
		"lilly": 0.0000070000, "limited": 0.0000010000, "limo": 0.0000010000,
		"link": 0.0008800000, "live": 0.0010920000, "living": 0.0000030000,
		"lk": 0.0000480000, "loan": 0.0000030000, "lol": 0.0002930000,
		"london": 0.0000070000, "love": 0.0000360000, "ls": 0.0000120000,
		"lt": 0.0001690000, "ltd": 0.0000770000, "lu": 0.0001890000,
		"luxury": 0.0000010000, "lv": 0.0001680000, "ly": 0.0001460000,
		"ma": 0.0000470000, "madrid": 0.0000020000, "makeup": 0.0000300000,
		"management": 0.0005200000, "market": 0.0000440000, "marketing": 0.0000200000,
		"markets": 0.0000090000, "mattel": 0.0000010000, "mba": 0.0000010000,
		"mc": 0.0000040000, "md": 0.0000990000, "me": 0.0028120000,
		"media": 0.0004310000, "meet": 0.0000050000, "meme": 0.0000060000,
		"memorial": 0.0000030000, "men": 0.0000140000, "menu": 0.0000230000,
		"mg": 0.0000190000, "microsoft": 0.0003820000, "mil": 0.0003610000,
		"mk": 0.0000210000, "ml": 0.0000600000, "mm": 0.0000300000,
		"mn": 0.0000100000, "mo": 0.0000130000, "mobi": 0.0014870000,
		"moe": 0.0000620000, "mom": 0.0000500000, "money": 0.0000270000,
		"monster": 0.0000570000, "mortgage": 0.0000030000, "moscow": 0.0000020000,
		"motorcycles": 0.0000290000, "mov": 0.0000100000, "movie": 0.0000040000,
		"mp": 0.0000040000, "ms": 0.0009530000, "mt": 0.0000190000,
		"mu": 0.0000130000, "museum": 0.0000090000, "mv": 0.0000170000,
		"mw": 0.0000050000, "mx": 0.0007770000, "my": 0.0003290000,
		"mz": 0.0000080000, "na": 0.0000160000, "name": 0.0001780000,
		"navy": 0.0000020000, "nc": 0.0000010000, "ne": 0.0000100000,
		"net": 0.1410060000, "net.au": 0.0000610000, "net.br": 0.0000400000,
		"network": 0.0006020000, "new": 0.0000080000, "news": 0.0001480000,
		"next": 0.0003570000, "nexus": 0.0000040000, "nf": 0.0000050000,
		"ng": 0.0000930000, "ngo": 0.0000020000, "nhk": 0.0000040000,
		"ni": 0.0000170000, "ninja": 0.0007810000, "nl": 0.0041120000,
		"no": 0.0007060000, "now": 0.0000140000, "np": 0.0000150000,
		"nr": 0.0000050000, "ntt": 0.0000040000, "nu": 0.0000540000,
		"nyc": 0.0000090000, "nz": 0.0001390000, "observer": 0.0000030000,
		"om": 0.0000380000, "one": 0.0003470000, "ong": 0.0000010000,
		"onl": 0.0000610000, "online": 0.0011720000, "ooo": 0.0000100000,
		"orange": 0.0000010000, "org": 0.0257060000, "org.uk": 0.0008670000,
		"ovh": 0.0000570000, "pa": 0.0000390000, "page": 0.0000740000,
		"paris": 0.0000050000, "partners": 0.0000180000, "parts": 0.0000040000,
		"party": 0.0000230000, "pe": 0.0001510000, "pet": 0.0000150000,
		"pg": 0.0000020000, "ph": 0.0005060000, "pharmacy": 0.0000040000,
		"philips": 0.0000070000, "photo": 0.0000140000, "photos": 0.0000180000,
		"pics": 0.0000980000, "pictures": 0.0000160000, "pink": 0.0000080000,
		"pioneer": 0.0000010000, "pizza": 0.0000050000, "pk": 0.0000880000,
		"pl": 0.0015370000, "place": 0.0000120000, "play": 0.0000010000,
		"plus": 0.0000760000, "pm": 0.0000250000, "pn": 0.0000110000,
		"politie": 0.0000010000, "porn": 0.0000390000, "pr": 0.0000110000,
		"press": 0.0000180000, "pro": 0.0021490000, "prod": 0.0000030000,
		"productions": 0.0000020000, "promo": 0.0000100000, "ps": 0.0000090000,
		"pt": 0.0005720000, "pub": 0.0001110000, "pw": 0.0001050000,
		"py": 0.0000130000, "qa": 0.0000300000, "qpon": 0.0000700000,
		"quest": 0.0000700000, "racing": 0.0000040000, "re": 0.0000530000,
		"realtor": 0.0000030000, "recipes": 0.0000030000, "red": 0.0000420000,
		"reisen": 0.0000030000, "ren": 0.0000100000, "rent": 0.0000060000,
		"rentals": 0.0000030000, "report": 0.0000140000, "republican": 0.0000020000,
		"rest": 0.0000470000, "restaurant": 0.0000120000, "review": 0.0000030000,
		"reviews": 0.0000070000, "rip": 0.0000110000, "ro": 0.0006480000,
		"rocks": 0.0000820000, "rodeo": 0.0000080000, "rs": 0.0001380000,
		"ru": 0.0080660000, "ruhr": 0.0000020000, "run": 0.0001330000,
		"rw": 0.0000100000, "sa": 0.0002010000, "sale": 0.0000100000,
		"salon": 0.0000020000, "sanofi": 0.0000040000, "sap": 0.0002720000,
		"saxo": 0.0000020000, "sb": 0.0000130000, "sbi": 0.0000020000,
		"sbs": 0.0003850000, "sc": 0.0000270000, "scb": 0.0000010000,
		"school": 0.0000170000, "schule": 0.0000010000, "schwarz": 0.0000230000,
		"science": 0.0000080000, "scot": 0.0000280000, "se": 0.0008180000,
		"security": 0.0000770000, "services": 0.0004760000, "sex": 0.0000110000,
		"sexy": 0.0000030000, "sg": 0.0003970000, "sh": 0.0002300000,
		"sharp": 0.0000020000, "show": 0.0000220000, "si": 0.0001340000,
		"site": 0.0009970000, "sk": 0.0004080000, "ski": 0.0000090000,
		"skin": 0.0000390000, "sky": 0.0000290000, "sl": 0.0000040000,
		"sm": 0.0000040000, "sn": 0.0000070000, "sncf": 0.0000020000,
		"so": 0.0001880000, "social": 0.0000510000, "software": 0.0000840000,
		"solar": 0.0000020000, "solutions": 0.0000990000, "sony": 0.0000010000,
		"space": 0.0003870000, "sr": 0.0000070000, "st": 0.0001370000,
		"statebank": 0.0000020000, "statefarm": 0.0000550000, "storage": 0.0000040000,
		"store": 0.0003190000, "stream": 0.0000520000, "studio": 0.0000850000,
		"study": 0.0000060000, "style": 0.0000040000, "su": 0.0001480000,
		"sucks": 0.0000020000, "supply": 0.0000100000, "support": 0.0001030000,
		"surf": 0.0000120000, "sv": 0.0000390000, "swiss": 0.0000190000,
		"sx": 0.0000210000, "sy": 0.0000010000, "sydney": 0.0000020000,
		"systems": 0.0003670000, "taipei": 0.0000030000, "tattoo": 0.0000020000,
		"tax": 0.0000030000, "taxi": 0.0000040000, "tc": 0.0000260000,
		"td": 0.0000040000, "team": 0.0001160000, "tech": 0.0013210000,
		"technology": 0.0000920000, "tel": 0.0000210000, "tf": 0.0000210000,
		"tg": 0.0000060000, "th": 0.0010050000, "tickets": 0.0000040000,
		"tips": 0.0000080000, "tj": 0.0000120000, "tk": 0.0000840000,
		"tl": 0.0000100000, "tm": 0.0000150000, "tn": 0.0000150000,
		"to": 0.0006050000, "today": 0.0000930000, "tokyo": 0.0000380000,
		"tools": 0.0001740000, "top": 0.0039890000, "total": 0.0000010000,
		"tours": 0.0000030000, "town": 0.0000160000, "toyota": 0.0000010000,
		"toys": 0.0000090000, "tr": 0.0010080000, "trade": 0.0000650000,
		"trading": 0.0000020000, "training": 0.0000170000, "travel": 0.0000820000,
		"tt": 0.0000230000, "tube": 0.0000460000, "tui": 0.0000060000,
		"tv": 0.0035510000, "tw": 0.0003270000, "tz": 0.0000090000,
		"ua": 0.0006500000, "ug": 0.0000700000, "uk": 0.0008450000,
		"university": 0.0000080000, "uno": 0.0000190000, "uol": 0.0000030000,
		"us": 0.0051920000, "uy": 0.0000510000, "uz": 0.0000600000,
		"va": 0.0000110000, "vc": 0.0000280000, "ve": 0.0000570000,
		"vegas": 0.0000010000, "ventures": 0.0000010000, "vet": 0.0000240000,
		"vg": 0.0000170000, "vi": 0.0000030000, "viajes": 0.0000020000,
		"video": 0.0003900000, "vig": 0.0000020000, "vin": 0.0000070000,
		"vip": 0.0007040000, "vision": 0.0000100000, "vlaanderen": 0.0000090000,
		"vn": 0.0016830000, "vote": 0.0000010000, "vu": 0.0000070000,
		"wales": 0.0000140000, "wang": 0.0000330000, "watch": 0.0000250000,
		"webcam": 0.0000100000, "website": 0.0001060000, "wedding": 0.0000020000,
		"wf": 0.0000120000, "wien": 0.0000020000, "wiki": 0.0001340000,
		"win": 0.0001430000, "windows": 0.0000030000, "wine": 0.0000070000,
		"work": 0.0002920000, "works": 0.0000620000, "world": 0.0001940000,
		"ws": 0.0001450000, "wtf": 0.0000480000, "xin": 0.0000570000,
		"xn--80asehdb": 0.0000020000, "xn--9dbq2a": 0.0000010000,
		"xn--fiqs8s": 0.0000040000, "xn--ngbc5azd": 0.0000010000,
		"xn--o3cw4h": 0.0000030000, "xn--p1ai": 0.0000300000,
		"xxx": 0.0001190000, "xyz": 0.0046600000, "yachts": 0.0000240000,
		"yandex": 0.0000040000, "yoga": 0.0000020000, "you": 0.0000010000,
		"youtube": 0.0000010000, "yt": 0.0000030000, "za": 0.0000490000,
		"zappos": 0.0000020000, "zip": 0.0000140000, "zm": 0.0000030000,
		"zone": 0.0002520000, "zw": 0.0000100000,
	}
)

// specialChars is the set of characters counted by F18 num_special_chars.
// Matches Python: "!@#$%^&*~`|\\<>{}"
const specialChars = "!@#$%^&*~`|\\<>{}"

// tokenSplitters is the set of runes used to split URL tokens for F30 token_count.
// Matches Python: re.split(r"[/\?&=\-\_\.\:\@\#\+\~\%]", url_str)
const tokenSplitters = "/?&=-_.:@#+~%"

// splitTLDParts returns (domain, subdomain, tld) for a lower-cased hostname.
//
// For ICANN-registered TLDs it uses the Public Suffix List via
// golang.org/x/net/publicsuffix, which matches the behaviour of Python's
// tldextract (used during training) for government and academic ccSLDs such
// as vic.gov.au, ac.at, gov.cn, or.kr, edu.au.
//
// For private PSL entries (e.g. workers.dev, repl.co, github.io) it falls
// back to a single-part TLD split, again matching tldextract's default
// include_psl_private_domains=False behaviour that was in effect during
// training (confirmed by num_subdomains values in cybersiren_lowlatency_dataset.csv).
func splitTLDParts(hostname string) (domain, subdomain, tld string) {
	if hostname == "" {
		return "", "", ""
	}

	// IP addresses have no TLD structure — match tldextract behaviour.
	if net.ParseIP(hostname) != nil {
		return hostname, "", ""
	}

	eTLD, icann := publicsuffix.PublicSuffix(hostname)
	if !icann {
		// Private domain — simple single-part TLD split.
		return splitTLDSimple(hostname)
	}

	tld = eTLD
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		// hostname IS the eTLD (e.g. bare "com").
		return hostname, "", tld
	}

	// domain = eTLDPlusOne minus its TLD suffix.
	if len(eTLDPlusOne) > len(tld)+1 {
		domain = eTLDPlusOne[:len(eTLDPlusOne)-len(tld)-1]
	} else {
		domain = eTLDPlusOne
	}

	// subdomain = everything in hostname before eTLDPlusOne.
	if len(hostname) > len(eTLDPlusOne)+1 {
		subdomain = hostname[:len(hostname)-len(eTLDPlusOne)-1]
	}
	return
}

// splitTLDSimple is a fallback for private PSL domains.
// It treats the last label as the TLD (e.g. "dev" for "foo.workers.dev").
func splitTLDSimple(hostname string) (domain, subdomain, tld string) {
	parts := strings.Split(hostname, ".")
	n := len(parts)
	switch {
	case n == 0 || (n == 1 && parts[0] == ""):
		return hostname, "", ""
	case n == 1:
		return parts[0], "", ""
	}
	tld = parts[n-1]
	domain = parts[n-2]
	if n > 2 {
		subdomain = strings.Join(parts[:n-2], ".")
	}
	return
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0.0
	}
	freq := make(map[rune]int, 64)
	total := 0
	for _, c := range s {
		freq[c]++
		total++
	}
	n := float64(total)
	var h float64
	for _, cnt := range freq {
		p := float64(cnt) / n
		h -= p * math.Log2(p)
	}
	return h
}

func computeURLCharProb(rawURL string) float64 {
	var sum float64
	var count int
	for _, c := range strings.ToLower(rawURL) {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			sum += charProbTable[c] // returns 0 for non-ASCII chars
			count++
		}
	}
	if count == 0 {
		return 0.0
	}
	return sum / float64(count)
}

func computeCharContinuationRate(s string) float64 {
	runes := []rune(s)
	if len(runes) == 0 {
		return 0.0
	}
	var ma, md, ms, ca, cd, cs int
	for _, c := range runes {
		switch {
		case unicode.IsLetter(c):
			ca++
			if ca > ma {
				ma = ca
			}
			cd, cs = 0, 0
		case unicode.IsDigit(c):
			cd++
			if cd > md {
				md = cd
			}
			ca, cs = 0, 0
		default:
			cs++
			if cs > ms {
				ms = cs
			}
			ca, cd = 0, 0
		}
	}
	return float64(ma+md+ms) / float64(len(runes))
}

// hasRepeatedDigits reports whether s contains 3+ consecutive identical digits.
// Replicates Python regex r"(\d)\1{2,}" without backreference support in Go.
func hasRepeatedDigitsFunc(s string) bool {
	var count int
	var last rune
	for _, c := range s {
		if unicode.IsDigit(c) {
			if c == last {
				count++
				if count >= 3 {
					return true
				}
			} else {
				count = 1
				last = c
			}
		} else {
			count = 0
			last = 0
		}
	}
	return false
}

// ExtractFeatures returns a 28-element float64 slice for rawURL.
// The feature order matches the Python training column order exactly.
// Returns a zero-filled slice (not an error) for empty or unparseable URLs.
func ExtractFeatures(rawURL string) ([]float64, error) {
	urlStr := strings.TrimSpace(rawURL)
	if urlStr == "" {
		return make([]float64, FeatureCount), nil
	}

	parseStr := urlStr
	if !strings.Contains(urlStr, "://") {
		parseStr = "http://" + urlStr
	}
	parsed, parseErr := url.Parse(parseStr)
	if parseErr != nil {
		return make([]float64, FeatureCount), fmt.Errorf("extract features: parse URL: %w", parseErr)
	}
	if parsed == nil {
		return make([]float64, FeatureCount), nil
	}

	hostname := strings.ToLower(parsed.Hostname())
	pathStr := parsed.Path
	queryStr := parsed.RawQuery
	fragment := parsed.Fragment
	scheme := strings.ToLower(parsed.Scheme)
	urlLower := strings.ToLower(urlStr)

	domain, subdomain, tld := splitTLDParts(hostname)

	var subParts []string
	if subdomain != "" {
		for _, p := range strings.Split(subdomain, ".") {
			if p != "" {
				subParts = append(subParts, p)
			}
		}
	}

	// ── F01 url_length ────────────────────────────────────────────────────────
	urlLength := float64(len(urlStr))

	// ── F02 num_dots ──────────────────────────────────────────────────────────
	numDots := float64(strings.Count(urlStr, "."))

	// ── F03 num_subdomains ────────────────────────────────────────────────────
	numSubdomains := float64(len(subParts))

	// ── F05 num_hyphens_url ───────────────────────────────────────────────────
	numHyphensURL := float64(strings.Count(urlStr, "-"))

	// ── F06 num_hyphens_hostname ──────────────────────────────────────────────
	numHyphensHostname := float64(strings.Count(hostname, "-"))

	// ── F07 https_flag ────────────────────────────────────────────────────────
	var httpsFlag float64
	if scheme == "https" {
		httpsFlag = 1
	}

	// ── F08 entropy_url ───────────────────────────────────────────────────────
	entropyURL := shannonEntropy(urlStr)

	// ── F09 num_numeric_chars ─────────────────────────────────────────────────
	var numNumeric float64
	for _, c := range urlStr {
		if unicode.IsDigit(c) {
			numNumeric++
		}
	}

	// ── F10 num_sensitive_words ───────────────────────────────────────────────
	var numSensitiveWords float64
	for _, w := range sensitiveWords {
		numSensitiveWords += float64(strings.Count(urlLower, w))
	}

	// ── F11 hostname_length ───────────────────────────────────────────────────
	hostnameLength := float64(len(hostname))

	// ── F12 path_length ───────────────────────────────────────────────────────
	pathLength := float64(len(pathStr))

	// ── F13 url_char_prob ─────────────────────────────────────────────────────
	urlCharProbVal := computeURLCharProb(urlStr)

	// ── F14 char_continuation_rate ────────────────────────────────────────────
	charContRate := computeCharContinuationRate(urlStr)

	// ── F15 tld_legit_prob ────────────────────────────────────────────────────
	tldLegitProbVal := tldLegitProb[tld]

	// ── F16 entropy_domain ────────────────────────────────────────────────────
	entropyDomain := shannonEntropy(domain)

	// ── F17 num_query_params ──────────────────────────────────────────────────
	var numQueryParams float64
	if queryStr != "" {
		numQueryParams = float64(len(strings.Split(queryStr, "&")))
	}

	// ── F18 num_special_chars ─────────────────────────────────────────────────
	var numSpecialChars float64
	for _, c := range urlStr {
		if strings.ContainsRune(specialChars, c) {
			numSpecialChars++
		}
	}

	// ── F19 at_symbol_present ─────────────────────────────────────────────────
	var atSymbol float64
	if strings.Contains(urlStr, "@") {
		atSymbol = 1
	}

	// ── F20 pct_numeric_chars ─────────────────────────────────────────────────
	pctNumeric := numNumeric / math.Max(float64(len(urlStr)), 1)

	// ── F21 suspicious_file_ext ───────────────────────────────────────────────
	var suspFileExt float64
	pathLower := strings.ToLower(pathStr)
	for ext := range suspiciousExts {
		if strings.HasSuffix(pathLower, ext) {
			suspFileExt = 1
			break
		}
	}

	// ── F22 path_depth ────────────────────────────────────────────────────────
	pathDepth := math.Max(float64(strings.Count(pathStr, "/")-1), 0)

	// ── F23 num_underscores ───────────────────────────────────────────────────
	numUnderscores := float64(strings.Count(urlStr, "_"))

	// ── F25 query_length ──────────────────────────────────────────────────────
	queryLength := float64(len(queryStr))

	// ── F26 has_fragment ──────────────────────────────────────────────────────
	var hasFragment float64
	if fragment != "" {
		hasFragment = 1
	}

	// ── F27 has_repeated_digits ───────────────────────────────────────────────
	var hasRepDigits float64
	if hasRepeatedDigitsFunc(urlStr) {
		hasRepDigits = 1
	}

	// ── F28 avg_subdomain_length ──────────────────────────────────────────────
	var avgSubdomainLen float64
	if len(subParts) > 0 {
		var total int
		for _, p := range subParts {
			total += len(p)
		}
		avgSubdomainLen = float64(total) / float64(len(subParts))
	}

	// ── F29 tld_length ────────────────────────────────────────────────────────
	tldLength := float64(len(tld))

	// ── F30 token_count ───────────────────────────────────────────────────────
	tokenCount := float64(len(strings.FieldsFunc(urlStr, func(c rune) bool {
		return strings.ContainsRune(tokenSplitters, c)
	})))

	return []float64{
		urlLength,         // F01
		numDots,           // F02
		numSubdomains,     // F03
		numHyphensURL,     // F05
		numHyphensHostname, // F06
		httpsFlag,         // F07
		entropyURL,        // F08
		numNumeric,        // F09
		numSensitiveWords, // F10
		hostnameLength,    // F11
		pathLength,        // F12
		urlCharProbVal,    // F13
		charContRate,      // F14
		tldLegitProbVal,   // F15
		entropyDomain,     // F16
		numQueryParams,    // F17
		numSpecialChars,   // F18
		atSymbol,          // F19
		pctNumeric,        // F20
		suspFileExt,       // F21
		pathDepth,         // F22
		numUnderscores,    // F23
		queryLength,       // F25
		hasFragment,       // F26
		hasRepDigits,      // F27
		avgSubdomainLen,   // F28
		tldLength,         // F29
		tokenCount,        // F30
	}, nil
}
