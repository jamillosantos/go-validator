package validator

// This file was copied from github.com/go-playground/validator (thanks).
// This library tries to make the implementation most compatible with it.

var iso3166_1_alpha2 = map[string]bool{
	// see: https://www.iso.org/iso-3166-country-codes.html
	"AF": true, "AX": true, "AL": true, "DZ": true, "AS": true,
	"AD": true, "AO": true, "AI": true, "AQ": true, "AG": true,
	"AR": true, "AM": true, "AW": true, "AU": true, "AT": true,
	"AZ": true, "BS": true, "BH": true, "BD": true, "BB": true,
	"BY": true, "BE": true, "BZ": true, "BJ": true, "BM": true,
	"BT": true, "BO": true, "BQ": true, "BA": true, "BW": true,
	"BV": true, "BR": true, "IO": true, "BN": true, "BG": true,
	"BF": true, "BI": true, "KH": true, "CM": true, "CA": true,
	"CV": true, "KY": true, "CF": true, "TD": true, "CL": true,
	"CN": true, "CX": true, "CC": true, "CO": true, "KM": true,
	"CG": true, "CD": true, "CK": true, "CR": true, "CI": true,
	"HR": true, "CU": true, "CW": true, "CY": true, "CZ": true,
	"DK": true, "DJ": true, "DM": true, "DO": true, "EC": true,
	"EG": true, "SV": true, "GQ": true, "ER": true, "EE": true,
	"ET": true, "FK": true, "FO": true, "FJ": true, "FI": true,
	"FR": true, "GF": true, "PF": true, "TF": true, "GA": true,
	"GM": true, "GE": true, "DE": true, "GH": true, "GI": true,
	"GR": true, "GL": true, "GD": true, "GP": true, "GU": true,
	"GT": true, "GG": true, "GN": true, "GW": true, "GY": true,
	"HT": true, "HM": true, "VA": true, "HN": true, "HK": true,
	"HU": true, "IS": true, "IN": true, "ID": true, "IR": true,
	"IQ": true, "IE": true, "IM": true, "IL": true, "IT": true,
	"JM": true, "JP": true, "JE": true, "JO": true, "KZ": true,
	"KE": true, "KI": true, "KP": true, "KR": true, "KW": true,
	"KG": true, "LA": true, "LV": true, "LB": true, "LS": true,
	"LR": true, "LY": true, "LI": true, "LT": true, "LU": true,
	"MO": true, "MK": true, "MG": true, "MW": true, "MY": true,
	"MV": true, "ML": true, "MT": true, "MH": true, "MQ": true,
	"MR": true, "MU": true, "YT": true, "MX": true, "FM": true,
	"MD": true, "MC": true, "MN": true, "ME": true, "MS": true,
	"MA": true, "MZ": true, "MM": true, "NA": true, "NR": true,
	"NP": true, "NL": true, "NC": true, "NZ": true, "NI": true,
	"NE": true, "NG": true, "NU": true, "NF": true, "MP": true,
	"NO": true, "OM": true, "PK": true, "PW": true, "PS": true,
	"PA": true, "PG": true, "PY": true, "PE": true, "PH": true,
	"PN": true, "PL": true, "PT": true, "PR": true, "QA": true,
	"RE": true, "RO": true, "RU": true, "RW": true, "BL": true,
	"SH": true, "KN": true, "LC": true, "MF": true, "PM": true,
	"VC": true, "WS": true, "SM": true, "ST": true, "SA": true,
	"SN": true, "RS": true, "SC": true, "SL": true, "SG": true,
	"SX": true, "SK": true, "SI": true, "SB": true, "SO": true,
	"ZA": true, "GS": true, "SS": true, "ES": true, "LK": true,
	"SD": true, "SR": true, "SJ": true, "SZ": true, "SE": true,
	"CH": true, "SY": true, "TW": true, "TJ": true, "TZ": true,
	"TH": true, "TL": true, "TG": true, "TK": true, "TO": true,
	"TT": true, "TN": true, "TR": true, "TM": true, "TC": true,
	"TV": true, "UG": true, "UA": true, "AE": true, "GB": true,
	"US": true, "UM": true, "UY": true, "UZ": true, "VU": true,
	"VE": true, "VN": true, "VG": true, "VI": true, "WF": true,
	"EH": true, "YE": true, "ZM": true, "ZW": true,
}

var iso3166_1_alpha3 = map[string]bool{
	// see: https://www.iso.org/iso-3166-country-codes.html
	"AFG": true, "ALB": true, "DZA": true, "ASM": true, "AND": true,
	"AGO": true, "AIA": true, "ATA": true, "ATG": true, "ARG": true,
	"ARM": true, "ABW": true, "AUS": true, "AUT": true, "AZE": true,
	"BHS": true, "BHR": true, "BGD": true, "BRB": true, "BLR": true,
	"BEL": true, "BLZ": true, "BEN": true, "BMU": true, "BTN": true,
	"BOL": true, "BES": true, "BIH": true, "BWA": true, "BVT": true,
	"BRA": true, "IOT": true, "BRN": true, "BGR": true, "BFA": true,
	"BDI": true, "CPV": true, "KHM": true, "CMR": true, "CAN": true,
	"CYM": true, "CAF": true, "TCD": true, "CHL": true, "CHN": true,
	"CXR": true, "CCK": true, "COL": true, "COM": true, "COD": true,
	"COG": true, "COK": true, "CRI": true, "HRV": true, "CUB": true,
	"CUW": true, "CYP": true, "CZE": true, "CIV": true, "DNK": true,
	"DJI": true, "DMA": true, "DOM": true, "ECU": true, "EGY": true,
	"SLV": true, "GNQ": true, "ERI": true, "EST": true, "SWZ": true,
	"ETH": true, "FLK": true, "FRO": true, "FJI": true, "FIN": true,
	"FRA": true, "GUF": true, "PYF": true, "ATF": true, "GAB": true,
	"GMB": true, "GEO": true, "DEU": true, "GHA": true, "GIB": true,
	"GRC": true, "GRL": true, "GRD": true, "GLP": true, "GUM": true,
	"GTM": true, "GGY": true, "GIN": true, "GNB": true, "GUY": true,
	"HTI": true, "HMD": true, "VAT": true, "HND": true, "HKG": true,
	"HUN": true, "ISL": true, "IND": true, "IDN": true, "IRN": true,
	"IRQ": true, "IRL": true, "IMN": true, "ISR": true, "ITA": true,
	"JAM": true, "JPN": true, "JEY": true, "JOR": true, "KAZ": true,
	"KEN": true, "KIR": true, "PRK": true, "KOR": true, "KWT": true,
	"KGZ": true, "LAO": true, "LVA": true, "LBN": true, "LSO": true,
	"LBR": true, "LBY": true, "LIE": true, "LTU": true, "LUX": true,
	"MAC": true, "MDG": true, "MWI": true, "MYS": true, "MDV": true,
	"MLI": true, "MLT": true, "MHL": true, "MTQ": true, "MRT": true,
	"MUS": true, "MYT": true, "MEX": true, "FSM": true, "MDA": true,
	"MCO": true, "MNG": true, "MNE": true, "MSR": true, "MAR": true,
	"MOZ": true, "MMR": true, "NAM": true, "NRU": true, "NPL": true,
	"NLD": true, "NCL": true, "NZL": true, "NIC": true, "NER": true,
	"NGA": true, "NIU": true, "NFK": true, "MKD": true, "MNP": true,
	"NOR": true, "OMN": true, "PAK": true, "PLW": true, "PSE": true,
	"PAN": true, "PNG": true, "PRY": true, "PER": true, "PHL": true,
	"PCN": true, "POL": true, "PRT": true, "PRI": true, "QAT": true,
	"ROU": true, "RUS": true, "RWA": true, "REU": true, "BLM": true,
	"SHN": true, "KNA": true, "LCA": true, "MAF": true, "SPM": true,
	"VCT": true, "WSM": true, "SMR": true, "STP": true, "SAU": true,
	"SEN": true, "SRB": true, "SYC": true, "SLE": true, "SGP": true,
	"SXM": true, "SVK": true, "SVN": true, "SLB": true, "SOM": true,
	"ZAF": true, "SGS": true, "SSD": true, "ESP": true, "LKA": true,
	"SDN": true, "SUR": true, "SJM": true, "SWE": true, "CHE": true,
	"SYR": true, "TWN": true, "TJK": true, "TZA": true, "THA": true,
	"TLS": true, "TGO": true, "TKL": true, "TON": true, "TTO": true,
	"TUN": true, "TUR": true, "TKM": true, "TCA": true, "TUV": true,
	"UGA": true, "UKR": true, "ARE": true, "GBR": true, "UMI": true,
	"USA": true, "URY": true, "UZB": true, "VUT": true, "VEN": true,
	"VNM": true, "VGB": true, "VIR": true, "WLF": true, "ESH": true,
	"YEM": true, "ZMB": true, "ZWE": true, "ALA": true,
}
var iso3166_1_alpha_numeric = map[int]bool{
	// see: https://www.iso.org/iso-3166-country-codes.html
	4: true, 8: true, 12: true, 16: true, 20: true,
	24: true, 660: true, 10: true, 28: true, 32: true,
	51: true, 533: true, 36: true, 40: true, 31: true,
	44: true, 48: true, 50: true, 52: true, 112: true,
	56: true, 84: true, 204: true, 60: true, 64: true,
	68: true, 535: true, 70: true, 72: true, 74: true,
	76: true, 86: true, 96: true, 100: true, 854: true,
	108: true, 132: true, 116: true, 120: true, 124: true,
	136: true, 140: true, 148: true, 152: true, 156: true,
	162: true, 166: true, 170: true, 174: true, 180: true,
	178: true, 184: true, 188: true, 191: true, 192: true,
	531: true, 196: true, 203: true, 384: true, 208: true,
	262: true, 212: true, 214: true, 218: true, 818: true,
	222: true, 226: true, 232: true, 233: true, 748: true,
	231: true, 238: true, 234: true, 242: true, 246: true,
	250: true, 254: true, 258: true, 260: true, 266: true,
	270: true, 268: true, 276: true, 288: true, 292: true,
	300: true, 304: true, 308: true, 312: true, 316: true,
	320: true, 831: true, 324: true, 624: true, 328: true,
	332: true, 334: true, 336: true, 340: true, 344: true,
	348: true, 352: true, 356: true, 360: true, 364: true,
	368: true, 372: true, 833: true, 376: true, 380: true,
	388: true, 392: true, 832: true, 400: true, 398: true,
	404: true, 296: true, 408: true, 410: true, 414: true,
	417: true, 418: true, 428: true, 422: true, 426: true,
	430: true, 434: true, 438: true, 440: true, 442: true,
	446: true, 450: true, 454: true, 458: true, 462: true,
	466: true, 470: true, 584: true, 474: true, 478: true,
	480: true, 175: true, 484: true, 583: true, 498: true,
	492: true, 496: true, 499: true, 500: true, 504: true,
	508: true, 104: true, 516: true, 520: true, 524: true,
	528: true, 540: true, 554: true, 558: true, 562: true,
	566: true, 570: true, 574: true, 807: true, 580: true,
	578: true, 512: true, 586: true, 585: true, 275: true,
	591: true, 598: true, 600: true, 604: true, 608: true,
	612: true, 616: true, 620: true, 630: true, 634: true,
	642: true, 643: true, 646: true, 638: true, 652: true,
	654: true, 659: true, 662: true, 663: true, 666: true,
	670: true, 882: true, 674: true, 678: true, 682: true,
	686: true, 688: true, 690: true, 694: true, 702: true,
	534: true, 703: true, 705: true, 90: true, 706: true,
	710: true, 239: true, 728: true, 724: true, 144: true,
	729: true, 740: true, 744: true, 752: true, 756: true,
	760: true, 158: true, 762: true, 834: true, 764: true,
	626: true, 768: true, 772: true, 776: true, 780: true,
	788: true, 792: true, 795: true, 796: true, 798: true,
	800: true, 804: true, 784: true, 826: true, 581: true,
	840: true, 858: true, 860: true, 548: true, 862: true,
	704: true, 92: true, 850: true, 876: true, 732: true,
	887: true, 894: true, 716: true, 248: true,
}