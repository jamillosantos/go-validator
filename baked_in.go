package validator

// This file was heavily based on github.com/go-playground/validator (thanks).
// This library tries to make the implementation most compatible with it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/sha3"

	urn "github.com/leodido/go-urn"
)

// Func accepts a FieldContext struct for all validation needs. The return
// value should be true when validation succeeds.
type Func func(fieldContext FieldContext) bool

// FuncCtx accepts a context.Context and FieldContext interface for all
// validation needs. The return value should be true when validation succeeds.
type FuncCtx func(ctx context.Context, fieldContext FieldContext) bool

// wrapFunc wraps noramal Func makes it compatible with FuncCtx
func wrapFunc(fn Func) FuncCtx {
	if fn == nil {
		return nil // be sure not to wrap a bad function.
	}
	return func(ctx context.Context, fieldContext FieldContext) bool {
		return fn(fieldContext)
	}
}

var (
	restrictedTags = map[string]struct{}{
		diveTag:           {},
		keysTag:           {},
		endKeysTag:        {},
		structOnlyTag:     {},
		omitempty:         {},
		skipValidationTag: {},
		utf8HexComma:      {},
		utf8Pipe:          {},
		noStructLevelTag:  {},
		requiredTag:       {},
		isdefault:         {},
	}

	// BakedInAliasValidators is a default mapping of a single validation tag that
	// defines a common or complex set of validation(s) to simplify
	// adding validation to structs.
	bakedInAliases = map[string]string{
		"iscolor":      "hexcolor|rgb|rgba|hsl|hsla",
		"country_code": "iso3166_1_alpha2|iso3166_1_alpha3|iso3166_1_alpha_numeric",
	}

	// BakedInValidators is the default map of ValidationFunc
	// you can add, remove or even replace items to suite your needs,
	// or even disregard and use your own map if so desired.
	bakedInValidators = map[string]Func{
		"required": hasValue,
		// "required_if":             requiredIf,
		// "required_unless":         requiredUnless,
		// "required_with":           requiredWith,
		// "required_with_all":       requiredWithAll,
		// "required_without":        requiredWithout,
		// "required_without_all":    requiredWithoutAll,
		// "excluded_with":           excludedWith,
		// "excluded_with_all":       excludedWithAll,
		// "excluded_without":        excludedWithout,
		// "excluded_without_all":    excludedWithoutAll,
		"isdefault": isDefault,
		// "len":                     hasLengthOf,
		// "min":                     hasMinOf,
		// "max":                     hasMaxOf,
		"eq": isEq,
		"ne": isNe,
		// "lt":                      isLt,
		// "lte":                     isLte,
		// "gt":                      isGt,
		// "gte":                     isGte,
		// "eqfield":                 isEqField,
		// "eqcsfield":               isEqCrossStructField,
		// "necsfield":               isNeCrossStructField,
		// "gtcsfield":               isGtCrossStructField,
		// "gtecsfield":              isGteCrossStructField,
		// "ltcsfield":               isLtCrossStructField,
		// "ltecsfield":              isLteCrossStructField,
		// "nefield":                 isNeField,
		// "gtefield":                isGteField,
		// "gtfield":                 isGtField,
		// "ltefield":                isLteField,
		// "ltfield":                 isLtField,
		// "fieldcontains":           fieldContains,
		// "fieldexcludes":           fieldExcludes,
		"alpha":            isAlpha,
		"alphanum":         isAlphanum,
		"alphaunicode":     isAlphaUnicode,
		"alphanumunicode":  isAlphanumUnicode,
		"numeric":          isNumeric,
		"number":           isNumber,
		"hexadecimal":      isHexadecimal,
		"hexcolor":         isHEXColor,
		"rgb":              isRGB,
		"rgba":             isRGBA,
		"hsl":              isHSL,
		"hsla":             isHSLA,
		"e164":             isE164,
		"email":            isEmail,
		"url":              isURL,
		"uri":              isURI,
		"urn_rfc2141":      isUrnRFC2141, // RFC 2141
		"file":             isFile,
		"base64":           isBase64,
		"base64url":        isBase64URL,
		"contains":         contains,
		"containsany":      containsAny,
		"containsrune":     containsRune,
		"excludes":         excludes,
		"excludesall":      excludesAll,
		"excludesrune":     excludesRune,
		"startswith":       startsWith,
		"endswith":         endsWith,
		"startsnotwith":    startsNotWith,
		"endsnotwith":      endsNotWith,
		"isbn":             isISBN,
		"isbn10":           isISBN10,
		"isbn13":           isISBN13,
		"eth_addr":         isEthereumAddress,
		"btc_addr":         isBitcoinAddress,
		"btc_addr_bech32":  isBitcoinBech32Address,
		"uuid":             isUUID,
		"uuid3":            isUUID3,
		"uuid4":            isUUID4,
		"uuid5":            isUUID5,
		"uuid_rfc4122":     isUUIDRFC4122,
		"uuid3_rfc4122":    isUUID3RFC4122,
		"uuid4_rfc4122":    isUUID4RFC4122,
		"uuid5_rfc4122":    isUUID5RFC4122,
		"ascii":            isASCII,
		"printascii":       isPrintableASCII,
		"multibyte":        hasMultiByteCharacter,
		"datauri":          isDataURI,
		"latitude":         isLatitude,
		"longitude":        isLongitude,
		"ssn":              isSSN,
		"ipv4":             isIPv4,
		"ipv6":             isIPv6,
		"ip":               isIP,
		"cidrv4":           isCIDRv4,
		"cidrv6":           isCIDRv6,
		"cidr":             isCIDR,
		"tcp4_addr":        isTCP4AddrResolvable,
		"tcp6_addr":        isTCP6AddrResolvable,
		"tcp_addr":         isTCPAddrResolvable,
		"udp4_addr":        isUDP4AddrResolvable,
		"udp6_addr":        isUDP6AddrResolvable,
		"udp_addr":         isUDPAddrResolvable,
		"ip4_addr":         isIP4AddrResolvable,
		"ip6_addr":         isIP6AddrResolvable,
		"ip_addr":          isIPAddrResolvable,
		"unix_addr":        isUnixAddrResolvable,
		"mac":              isMAC,
		"hostname":         isHostnameRFC952,  // RFC 952
		"hostname_rfc1123": isHostnameRFC1123, // RFC 1123
		"fqdn":             isFQDN,
		// "unique":                  isUnique,
		"oneof":                   isOneOf,
		"html":                    isHTML,
		"html_encoded":            isHTMLEncoded,
		"url_encoded":             isURLEncoded,
		"dir":                     isDir,
		"json":                    isJSON,
		"hostname_port":           isHostnamePort,
		"lowercase":               isLowercase,
		"uppercase":               isUppercase,
		"datetime":                isDatetime,
		"timezone":                isTimeZone,
		"iso3166_1_alpha2":        isIso3166Alpha2,
		"iso3166_1_alpha3":        isIso3166Alpha3,
		"iso3166_1_alpha_numeric": isIso3166AlphaNumeric,
	}
)

var oneofValsCache = map[string][]string{}
var oneofValsCacheRWLock = sync.RWMutex{}

func parseOneOfParam2(s string) []string {
	oneofValsCacheRWLock.RLock()
	vals, ok := oneofValsCache[s]
	oneofValsCacheRWLock.RUnlock()
	if !ok {
		oneofValsCacheRWLock.Lock()
		vals = splitParamsRegex.FindAllString(s, -1)
		for i := 0; i < len(vals); i++ {
			vals[i] = strings.Replace(vals[i], "'", "", -1)
		}
		oneofValsCache[s] = vals
		oneofValsCacheRWLock.Unlock()
	}
	return vals
}

func fieldContextAsString(fieldContext FieldContext) (string, bool) {
	switch value := fieldContext.Value.(type) {
	case string:
		return value, true
	case *string:
		if value == nil {
			return "", true
		}
		return *value, true
	case fmt.Stringer:
		return value.String(), true
	default:
		return "", false
	}
}

func isURLEncoded(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return URLEncodedRegex.MatchString(value)
}

func isHTMLEncoded(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return HTMLEncodedRegex.MatchString(value)
}

func isHTML(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return HTMLRegex.MatchString(value)
}

func isOneOf(fieldContext FieldContext) bool {
	var v string
	switch fieldValue := fieldContext.Value.(type) {
	case string:
		v = fieldValue
	case *string:
		if fieldValue != nil {
			v = *fieldValue
		}
	case fmt.Stringer:
		if fieldValue != nil {
			v = fieldValue.String()
		}
	case int:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int8:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int16:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int32:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int64:
		v = strconv.FormatInt(fieldValue, 10)
	case uint:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint8:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint16:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint32:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint64:
		v = strconv.FormatUint(fieldValue, 10)
	default:
		panic(fmt.Sprintf("Bad field type %T", fieldContext.Value))
	}
	for _, param := range fieldContext.Params {
		if param == v {
			return true
		}
	}
	return false
}

/*
// isUnique is the validation function for validating if each array|slice|map value is unique
func isUnique(fieldContext FieldContext) bool {

	field := fl.Field()
	param := fl.Param()
	v := reflect.ValueOf(struct{}{})

	switch field.Kind() {
	case reflect.Slice, reflect.Array:
		elem := field.Type().Elem()
		if elem.Kind() == reflect.Ptr {
			elem = elem.Elem()
		}

		if param == "" {
			m := reflect.MakeMap(reflect.MapOf(elem, v.Type()))

			for i := 0; i < field.Len(); i++ {
				m.SetMapIndex(reflect.Indirect(field.Index(i)), v)
			}
			return field.Len() == m.Len()
		}

		sf, ok := elem.FieldByName(param)
		if !ok {
			panic(fmt.Sprintf("Bad field name %s", param))
		}

		sfTyp := sf.Type
		if sfTyp.Kind() == reflect.Ptr {
			sfTyp = sfTyp.Elem()
		}

		m := reflect.MakeMap(reflect.MapOf(sfTyp, v.Type()))
		for i := 0; i < field.Len(); i++ {
			m.SetMapIndex(reflect.Indirect(reflect.Indirect(field.Index(i)).FieldByName(param)), v)
		}
		return field.Len() == m.Len()
	case reflect.Map:
		m := reflect.MakeMap(reflect.MapOf(field.Type().Elem(), v.Type()))

		for _, k := range field.MapKeys() {
			m.SetMapIndex(field.MapIndex(k), v)
		}
		return field.Len() == m.Len()
	default:
		panic(fmt.Sprintf("Bad field type %T", field.Interface()))
	}
}
*/

// IsMAC is the validation function for validating if the field's value is a valid MAC address.
func isMAC(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	_, err := net.ParseMAC(value)
	return err == nil
}

// IsCIDRv4 is the validation function for validating if the field's value is a valid v4 CIDR address.
func isCIDRv4(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	ip, _, err := net.ParseCIDR(value)

	return err == nil && ip.To4() != nil
}

// IsCIDRv6 is the validation function for validating if the field's value is a valid v6 CIDR address.
func isCIDRv6(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	ip, _, err := net.ParseCIDR(value)

	return err == nil && ip.To4() == nil
}

// IsCIDR is the validation function for validating if the field's value is a valid v4 or v6 CIDR address.
func isCIDR(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, _, err := net.ParseCIDR(value)

	return err == nil
}

// IsIPv4 is the validation function for validating if a value is a valid v4 IP address.
func isIPv4(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	ip := net.ParseIP(value)

	return ip != nil && ip.To4() != nil
}

// IsIPv6 is the validation function for validating if the field's value is a valid v6 IP address.
func isIPv6(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	ip := net.ParseIP(value)

	return ip != nil && ip.To4() == nil
}

// IsIP is the validation function for validating if the field's value is a valid v4 or v6 IP address.
func isIP(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	ip := net.ParseIP(value)

	return ip != nil
}

// IsSSN is the validation function for validating if the field's value is a valid SSN.
func isSSN(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return len(value) == 11 && SSNRegex.MatchString(value)
}

// IsLongitude is the validation function for validating if the field's value is a valid longitude coordinate.
func isLongitude(fieldContext FieldContext) bool {
	var v string
	switch fieldValue := fieldContext.Value.(type) {
	case string:
		v = fieldValue
	case *string:
		if fieldValue != nil {
			v = *fieldValue
		}
	case fmt.Stringer:
		if fieldValue != nil {
			v = fieldValue.String()
		}
	case int:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int8:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int16:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int32:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int64:
		v = strconv.FormatInt(fieldValue, 10)
	case uint:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint8:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint16:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint32:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint64:
		v = strconv.FormatUint(fieldValue, 10)
	case float32:
		v = strconv.FormatFloat(float64(fieldValue), 'f', -1, 32)
	case float64:
		v = strconv.FormatFloat(fieldValue, 'f', -1, 64)
	default:
		panic(fmt.Sprintf("Bad field type %T", fieldValue))
	}

	return LongitudeRegex.MatchString(v)
}

// IsLatitude is the validation function for validating if the field's value is a valid latitude coordinate.
func isLatitude(fieldContext FieldContext) bool {
	var v string
	switch fieldValue := fieldContext.Value.(type) {
	case string:
		v = fieldValue
	case *string:
		if fieldValue != nil {
			v = *fieldValue
		}
	case fmt.Stringer:
		if fieldValue != nil {
			v = fieldValue.String()
		}
	case int:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int8:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int16:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int32:
		v = strconv.FormatInt(int64(fieldValue), 10)
	case int64:
		v = strconv.FormatInt(fieldValue, 10)
	case uint:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint8:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint16:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint32:
		v = strconv.FormatUint(uint64(fieldValue), 10)
	case uint64:
		v = strconv.FormatUint(fieldValue, 10)
	case float32:
		v = strconv.FormatFloat(float64(fieldValue), 'f', -1, 32)
	case float64:
		v = strconv.FormatFloat(fieldValue, 'f', -1, 64)
	default:
		panic(fmt.Sprintf("Bad field type %T", fieldValue))
	}

	return LatitudeRegex.MatchString(v)
}

// IsDataURI is the validation function for validating if the field's value is a valid data URI.
func isDataURI(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	uri := strings.SplitN(value, ",", 2)

	if len(uri) != 2 {
		return false
	}

	if !DataURIRegex.MatchString(uri[0]) {
		return false
	}

	return Base64Regex.MatchString(uri[1])
}

// HasMultiByteCharacter is the validation function for validating if the field's value has a multi byte character.
func hasMultiByteCharacter(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return len(value) == 0 || MultibyteRegex.MatchString(value)
}

// IsPrintableASCII is the validation function for validating if the field's value is a valid printable ASCII character.
func isPrintableASCII(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return PrintableASCIIRegex.MatchString(value)
}

// IsASCII is the validation function for validating if the field's value is a valid ASCII character.
func isASCII(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return ASCIIRegex.MatchString(value)
}

// IsUUID5 is the validation function for validating if the field's value is a valid v5 UUID.
func isUUID5(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUID5Regex.MatchString(value)
}

// IsUUID4 is the validation function for validating if the field's value is a valid v4 UUID.
func isUUID4(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUID4Regex.MatchString(value)
}

// IsUUID3 is the validation function for validating if the field's value is a valid v3 UUID.
func isUUID3(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUID3Regex.MatchString(value)
}

// IsUUID is the validation function for validating if the field's value is a valid UUID of any version.
func isUUID(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUIDRegex.MatchString(value)
}

// IsUUID5RFC4122 is the validation function for validating if the field's value is a valid RFC4122 v5 UUID.
func isUUID5RFC4122(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUID5RFC4122Regex.MatchString(value)
}

// IsUUID4RFC4122 is the validation function for validating if the field's value is a valid RFC4122 v4 UUID.
func isUUID4RFC4122(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUID4RFC4122Regex.MatchString(value)
}

// IsUUID3RFC4122 is the validation function for validating if the field's value is a valid RFC4122 v3 UUID.
func isUUID3RFC4122(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUID3RFC4122Regex.MatchString(value)
}

// IsUUIDRFC4122 is the validation function for validating if the field's value is a valid RFC4122 UUID of any version.
func isUUIDRFC4122(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return UUIDRFC4122Regex.MatchString(value)
}

// IsISBN is the validation function for validating if the field's value is a valid v10 or v13 ISBN.
func isISBN(fieldContext FieldContext) bool {
	return isISBN10(fieldContext) || isISBN13(fieldContext)
}

// IsISBN13 is the validation function for validating if the field's value is a valid v13 ISBN.
func isISBN13(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	s := strings.Replace(strings.Replace(value, "-", "", 4), " ", "", 4)

	if !ISBN13Regex.MatchString(s) {
		return false
	}

	var checksum int32
	var i int32

	factor := []int32{1, 3}

	for i = 0; i < 12; i++ {
		checksum += factor[i%2] * int32(s[i]-'0')
	}

	return (int32(s[12]-'0'))-((10-(checksum%10))%10) == 0
}

// IsISBN10 is the validation function for validating if the field's value is a valid v10 ISBN.
func isISBN10(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	s := strings.Replace(strings.Replace(value, "-", "", 3), " ", "", 3)

	if !ISBN10Regex.MatchString(s) {
		return false
	}

	var checksum int32
	var i int32

	for i = 0; i < 9; i++ {
		checksum += (i + 1) * int32(s[i]-'0')
	}

	if s[9] == 'X' {
		checksum += 10 * 10
	} else {
		checksum += 10 * int32(s[9]-'0')
	}

	return checksum%11 == 0
}

// IsEthereumAddress is the validation function for validating if the field's value is a valid Ethereum address.
func isEthereumAddress(fieldContext FieldContext) bool {
	address, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	if !EthAddressRegex.MatchString(address) {
		return false
	}

	if EthaddressRegexUpper.MatchString(address) || EthAddressRegexLower.MatchString(address) {
		return true
	}

	// Checksum validation. Reference: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
	address = address[2:] // Skip "0x" prefix.
	h := sha3.NewLegacyKeccak256()
	// hash.Hash's io.Writer implementation says it never returns an error. https://golang.org/pkg/hash/#Hash
	_, _ = h.Write([]byte(strings.ToLower(address)))
	hash := hex.EncodeToString(h.Sum(nil))

	for i := 0; i < len(address); i++ {
		if address[i] <= '9' { // Skip 0-9 digits: they don't have upper/lower-case.
			continue
		}
		if hash[i] > '7' && address[i] >= 'a' || hash[i] <= '7' && address[i] <= 'F' {
			return false
		}
	}

	return true
}

// IsBitcoinAddress is the validation function for validating if the field's value is a valid btc address
func isBitcoinAddress(fieldContext FieldContext) bool {
	address, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	if !BtcAddressRegex.MatchString(address) {
		return false
	}

	alphabet := []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

	decode := [25]byte{}

	for _, n := range []byte(address) {
		d := bytes.IndexByte(alphabet, n)

		for i := 24; i >= 0; i-- {
			d += 58 * int(decode[i])
			decode[i] = byte(d % 256)
			d /= 256
		}
	}

	h := sha256.New()
	_, _ = h.Write(decode[:21])
	d := h.Sum([]byte{})
	h = sha256.New()
	_, _ = h.Write(d)

	validchecksum := [4]byte{}
	computedchecksum := [4]byte{}

	copy(computedchecksum[:], h.Sum(d[:0]))
	copy(validchecksum[:], decode[21:])

	return validchecksum == computedchecksum
}

// IsBitcoinBech32Address is the validation function for validating if the field's value is a valid bech32 btc address
func isBitcoinBech32Address(fieldContext FieldContext) bool {
	address, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	if !BtcLowerAddressRegexBech32.MatchString(address) && !BtcUpperAddressRegexBech32.MatchString(address) {
		return false
	}

	am := len(address) % 8

	if am == 0 || am == 3 || am == 5 {
		return false
	}

	address = strings.ToLower(address)

	alphabet := "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	hr := []int{3, 3, 0, 2, 3} // the human readable part will always be bc
	addr := address[3:]
	dp := make([]int, 0, len(addr))

	for _, c := range addr {
		dp = append(dp, strings.IndexRune(alphabet, c))
	}

	ver := dp[0]

	if ver < 0 || ver > 16 {
		return false
	}

	if ver == 0 {
		if len(address) != 42 && len(address) != 62 {
			return false
		}
	}

	values := append(hr, dp...)

	GEN := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

	p := 1

	for _, v := range values {
		b := p >> 25
		p = (p&0x1ffffff)<<5 ^ v

		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				p ^= GEN[i]
			}
		}
	}

	if p != 1 {
		return false
	}

	b := uint(0)
	acc := 0
	mv := (1 << 5) - 1
	var sw []int

	for _, v := range dp[1 : len(dp)-6] {
		acc = (acc << 5) | v
		b += 5
		for b >= 8 {
			b -= 8
			sw = append(sw, (acc>>b)&mv)
		}
	}

	if len(sw) < 2 || len(sw) > 40 {
		return false
	}

	return true
}

// ExcludesRune is the validation function for validating that the field's value does not contain the rune specified within the param.
func excludesRune(fieldContext FieldContext) bool {
	return !containsRune(fieldContext)
}

// ExcludesAll is the validation function for validating that the field's value does not contain any of the characters specified within the param.
func excludesAll(fieldContext FieldContext) bool {
	return !containsAny(fieldContext)
}

// Excludes is the validation function for validating that the field's value does not contain the text specified within the param.
func excludes(fieldContext FieldContext) bool {
	return !contains(fieldContext)
}

// ContainsRune is the validation function for validating that the field's value contains the rune specified within the param.
func containsRune(fieldContext FieldContext) bool {
	if len(fieldContext.Params) == 0 {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	r, _ := utf8.DecodeRuneInString(fieldContext.Params[0])

	return strings.ContainsRune(value, r)
}

// ContainsAny is the validation function for validating that the field's value contains any of the characters specified within the param.
func containsAny(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	for _, param := range fieldContext.Params {
		r := strings.ContainsAny(value, param)
		if r {
			return true
		}
	}
	return false
}

// Contains is the validation function for validating that the field's value contains the text specified within the param.
func contains(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	for _, param := range fieldContext.Params {
		r := strings.Contains(value, param)
		if r {
			return true
		}
	}
	return false
}

// StartsWith is the validation function for validating that the field's value starts with the text specified within the param.
func startsWith(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	for _, param := range fieldContext.Params {
		r := strings.HasPrefix(value, param)
		if r {
			return true
		}
	}
	return false
}

// EndsWith is the validation function for validating that the field's value ends with the text specified within the param.
func endsWith(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	for _, param := range fieldContext.Params {
		r := strings.HasSuffix(value, param)
		if r {
			return true
		}
	}
	return false
}

// StartsNotWith is the validation function for validating that the field's value does not start with the text specified within the param.
func startsNotWith(fieldContext FieldContext) bool {
	return !startsWith(fieldContext)
}

// EndsNotWith is the validation function for validating that the field's value does not end with the text specified within the param.
func endsNotWith(fieldContext FieldContext) bool {
	return !endsWith(fieldContext)
}

/*
// TODO(Jota): To work on this.

// FieldContains is the validation function for validating if the current field's value contains the field specified by the param's value.
func fieldContains(fieldContext FieldContext) bool {
	field := fl.Field()

	currentField, _, ok := fl.GetStructFieldOK()

	if !ok {
		return false
	}

	return strings.Contains(field.String(), currentField.String())
}
*/

/*
// TODO(Jota): To work on this.

// FieldExcludes is the validation function for validating if the current field's value excludes the field specified by the param's value.
func fieldExcludes(fieldContext FieldContext) bool {
	field := fl.Field()

	currentField, _, ok := fl.GetStructFieldOK()
	if !ok {
		return true
	}

	return !strings.Contains(field.String(), currentField.String())
}
*/

/*
// TODO(Jota): To work on this.

// IsNeField is the validation function for validating if the current field's value is not equal to the field specified by the param's value.
func isNeField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	currentField, currentKind, ok := fl.GetStructFieldOK()

	if !ok || currentKind != kind {
		return true
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() != currentField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() != currentField.Uint()

	case reflect.Float32, reflect.Float64:
		return field.Float() != currentField.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(field.Len()) != int64(currentField.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != currentField.Type() {
			return true
		}

		if fieldType == timeType {

			t := currentField.Interface().(time.Time)
			fieldTime := field.Interface().(time.Time)

			return !fieldTime.Equal(t)
		}

	}

	// default reflect.String:
	return field.String() != currentField.String()
}
*/

// IsNe is the validation function for validating that the field's value does not equal the provided param value.
func isNe(fieldContext FieldContext) bool {
	return !isEq(fieldContext)
}

/*
// TODO(Jota): To work on this.

// IsLteCrossStructField is the validation function for validating if the current field's value is less than or equal to the field, within a separate struct, specified by the param's value.
func isLteCrossStructField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	topField, topKind, ok := fl.GetStructFieldOK()
	if !ok || topKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() <= topField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() <= topField.Uint()

	case reflect.Float32, reflect.Float64:
		return field.Float() <= topField.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(field.Len()) <= int64(topField.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != topField.Type() {
			return false
		}

		if fieldType == timeType {

			fieldTime := field.Interface().(time.Time)
			topTime := topField.Interface().(time.Time)

			return fieldTime.Before(topTime) || fieldTime.Equal(topTime)
		}
	}

	// default reflect.String:
	return field.String() <= topField.String()
}
*/

/*
// TODO(Jota): To work on this.

// IsLtCrossStructField is the validation function for validating if the current field's value is less than the field, within a separate struct, specified by the param's value.
// NOTE: This is exposed for use within your own custom functions and not intended to be called directly.
func isLtCrossStructField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	topField, topKind, ok := fl.GetStructFieldOK()
	if !ok || topKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() < topField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() < topField.Uint()

	case reflect.Float32, reflect.Float64:
		return field.Float() < topField.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(field.Len()) < int64(topField.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != topField.Type() {
			return false
		}

		if fieldType == timeType {

			fieldTime := field.Interface().(time.Time)
			topTime := topField.Interface().(time.Time)

			return fieldTime.Before(topTime)
		}
	}

	// default reflect.String:
	return field.String() < topField.String()
}
*/

/*
// TODO(Jota): To work on this.

// IsGteCrossStructField is the validation function for validating if the current field's value is greater than or equal to the field, within a separate struct, specified by the param's value.
func isGteCrossStructField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	topField, topKind, ok := fl.GetStructFieldOK()
	if !ok || topKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() >= topField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() >= topField.Uint()

	case reflect.Float32, reflect.Float64:
		return field.Float() >= topField.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(field.Len()) >= int64(topField.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != topField.Type() {
			return false
		}

		if fieldType == timeType {

			fieldTime := field.Interface().(time.Time)
			topTime := topField.Interface().(time.Time)

			return fieldTime.After(topTime) || fieldTime.Equal(topTime)
		}
	}

	// default reflect.String:
	return field.String() >= topField.String()
}
*/

/*
// TODO(Jota): To work on this.

// IsGtCrossStructField is the validation function for validating if the current field's value is greater than the field, within a separate struct, specified by the param's value.
func isGtCrossStructField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	topField, topKind, ok := fl.GetStructFieldOK()
	if !ok || topKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() > topField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() > topField.Uint()

	case reflect.Float32, reflect.Float64:
		return field.Float() > topField.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(field.Len()) > int64(topField.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != topField.Type() {
			return false
		}

		if fieldType == timeType {

			fieldTime := field.Interface().(time.Time)
			topTime := topField.Interface().(time.Time)

			return fieldTime.After(topTime)
		}
	}

	// default reflect.String:
	return field.String() > topField.String()
}
*/

/*
// TODO(Jota): To work on this.

// IsNeCrossStructField is the validation function for validating that the current field's value is not equal to the field, within a separate struct, specified by the param's value.
func isNeCrossStructField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	topField, currentKind, ok := fl.GetStructFieldOK()
	if !ok || currentKind != kind {
		return true
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return topField.Int() != field.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return topField.Uint() != field.Uint()

	case reflect.Float32, reflect.Float64:
		return topField.Float() != field.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(topField.Len()) != int64(field.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != topField.Type() {
			return true
		}

		if fieldType == timeType {

			t := field.Interface().(time.Time)
			fieldTime := topField.Interface().(time.Time)

			return !fieldTime.Equal(t)
		}
	}

	// default reflect.String:
	return topField.String() != field.String()
}
*/

/*
// TODO(Jota): To work on this.

// IsEqCrossStructField is the validation function for validating that the current field's value is equal to the field, within a separate struct, specified by the param's value.
func isEqCrossStructField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	topField, topKind, ok := fl.GetStructFieldOK()
	if !ok || topKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return topField.Int() == field.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return topField.Uint() == field.Uint()

	case reflect.Float32, reflect.Float64:
		return topField.Float() == field.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(topField.Len()) == int64(field.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != topField.Type() {
			return false
		}

		if fieldType == timeType {

			t := field.Interface().(time.Time)
			fieldTime := topField.Interface().(time.Time)

			return fieldTime.Equal(t)
		}
	}

	// default reflect.String:
	return topField.String() == field.String()
}
*/

/*
// TODO(Jota): To work on this.

// IsEqField is the validation function for validating if the current field's value is equal to the field specified by the param's value.
func isEqField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	currentField, currentKind, ok := fl.GetStructFieldOK()
	if !ok || currentKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() == currentField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() == currentField.Uint()

	case reflect.Float32, reflect.Float64:
		return field.Float() == currentField.Float()

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(field.Len()) == int64(currentField.Len())

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != currentField.Type() {
			return false
		}

		if fieldType == timeType {

			t := currentField.Interface().(time.Time)
			fieldTime := field.Interface().(time.Time)

			return fieldTime.Equal(t)
		}

	}

	// default reflect.String:
	return field.String() == currentField.String()
}
*/

// IsEq is the validation function for validating if the current field's value is equal to the param's value.
func isEq(fieldContext FieldContext) bool {

	for _, param := range fieldContext.Params {

		switch fieldValue := fieldContext.Value.(type) {
		case string:
			if fieldValue == param {
				return true
			}
		case *string:
			if (fieldValue != nil && *fieldValue == param) || (fieldValue == nil && param == "") {
				return true
			}
		case fmt.Stringer:
			if (fieldValue != nil && fieldValue.String() == param) || (fieldValue == nil && param == "") {
				return true
			}

			/*
					// TODO(Jota): To work on this
				case reflect.Slice, reflect.Map, reflect.Array:
					p := asInt(param)

					return int64(field.Len()) == p
			*/

		case int:
			p, err := strconv.ParseInt(param, 10, 32)
			if err != nil {
				continue
			}
			return int64(fieldValue) == p
		case *int:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseInt(param, 10, 32)
			if err != nil {
				continue
			}
			return int64(*fieldValue) == p
		case int8:
			p, err := strconv.ParseInt(param, 10, 8)
			if err != nil {
				continue
			}
			return int64(fieldValue) == p
		case *int8:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseInt(param, 10, 8)
			if err != nil {
				continue
			}
			return int64(*fieldValue) == p
		case int16:
			p, err := strconv.ParseInt(param, 10, 16)
			if err != nil {
				continue
			}
			return int64(fieldValue) == p
		case *int16:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseInt(param, 10, 16)
			if err != nil {
				continue
			}
			return int64(*fieldValue) == p
		case int32:
			p, err := strconv.ParseInt(param, 10, 32)
			if err != nil {
				continue
			}
			return int64(fieldValue) == p
		case *int32:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseInt(param, 10, 32)
			if err != nil {
				continue
			}
			return int64(*fieldValue) == p
		case int64:
			p, err := strconv.ParseInt(param, 10, 64)
			if err != nil {
				continue
			}
			return fieldValue == p
		case *int64:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseInt(param, 10, 64)
			if err != nil {
				continue
			}
			return *fieldValue == p
		case uint:
			p, err := strconv.ParseUint(param, 10, 32)
			if err != nil {
				continue
			}
			return uint64(fieldValue) == p
		case *uint:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseUint(param, 10, 32)
			if err != nil {
				continue
			}
			return uint64(*fieldValue) == p
		case uint8:
			p, err := strconv.ParseUint(param, 10, 8)
			if err != nil {
				continue
			}
			return uint64(fieldValue) == p
		case *uint8:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseUint(param, 10, 8)
			if err != nil {
				continue
			}
			return uint64(*fieldValue) == p
		case uint16:
			p, err := strconv.ParseUint(param, 10, 16)
			if err != nil {
				continue
			}
			return uint64(fieldValue) == p
		case *uint16:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseUint(param, 10, 16)
			if err != nil {
				continue
			}
			return uint64(*fieldValue) == p
		case uint32:
			p, err := strconv.ParseUint(param, 10, 32)
			if err != nil {
				continue
			}
			return uint64(fieldValue) == p
		case *uint32:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseUint(param, 10, 32)
			if err != nil {
				continue
			}
			return uint64(*fieldValue) == p
		case uint64:
			p, err := strconv.ParseUint(param, 10, 64)
			if err != nil {
				continue
			}
			return fieldValue == p
		case *uint64:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseUint(param, 10, 64)
			if err != nil {
				continue
			}
			return *fieldValue == p
		case float32:
			p, err := strconv.ParseFloat(param, 32)
			if err != nil {
				continue
			}
			return float64(fieldValue) == p
		case *float32:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseFloat(param, 32)
			if err != nil {
				continue
			}
			return float64(*fieldValue) == p
		case float64:
			p, err := strconv.ParseFloat(param, 64)
			if err != nil {
				continue
			}
			return float64(fieldValue) == p
		case *float64:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseFloat(param, 64)
			if err != nil {
				continue
			}
			return float64(*fieldValue) == p
		case complex64:
			p, err := strconv.ParseComplex(param, 64)
			if err != nil {
				continue
			}
			return complex128(fieldValue) == p
		case *complex64:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseComplex(param, 64)
			if err != nil {
				continue
			}
			return complex128(*fieldValue) == p
		case complex128:
			p, err := strconv.ParseComplex(param, 128)
			if err != nil {
				continue
			}
			return complex128(fieldValue) == p
		case *complex128:
			if fieldValue == nil {
				continue
			}
			p, err := strconv.ParseComplex(param, 128)
			if err != nil {
				continue
			}
			return complex128(*fieldValue) == p
		case bool:
			p, err := strconv.ParseBool(param)
			if err != nil {
				continue
			}
			return fieldValue == p
		case *bool:
			p, err := strconv.ParseBool(param)
			if err != nil {
				continue
			}
			return *fieldValue == p
		default:
			panic(fmt.Sprintf("Bad field type %T", fieldValue))
		}
	}
	return false
}

// IsBase64 is the validation function for validating if the current field's value is a valid base 64.
func isBase64(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return Base64Regex.MatchString(value)
}

// IsBase64URL is the validation function for validating if the current field's value is a valid base64 URL safe string.
func isBase64URL(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return Base64URLRegex.MatchString(value)
}

// IsURI is the validation function for validating if the current field's value is a valid URI.
func isURI(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	// checks needed as of Go 1.6 because of change https://github.com/golang/go/commit/617c93ce740c3c3cc28cdd1a0d712be183d0b328#diff-6c2d018290e298803c0c9419d8739885L195
	// emulate browser and strip the '#' suffix prior to validation. see issue-#237
	if i := strings.Index(value, "#"); i > -1 {
		value = value[:i]
	}

	if len(value) == 0 {
		return false
	}

	_, err := url.ParseRequestURI(value)

	return err == nil
}

// IsURL is the validation function for validating if the current field's value is a valid URL.
func isURL(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	var i int

	// checks needed as of Go 1.6 because of change https://github.com/golang/go/commit/617c93ce740c3c3cc28cdd1a0d712be183d0b328#diff-6c2d018290e298803c0c9419d8739885L195
	// emulate browser and strip the '#' suffix prior to validation. see issue-#237
	if i = strings.Index(value, "#"); i > -1 {
		value = value[:i]
	}

	if len(value) == 0 {
		return false
	}

	url, err := url.ParseRequestURI(value)

	if err != nil || url.Scheme == "" {
		return false
	}

	return true
}

// isUrnRFC2141 is the validation function for validating if the current field's value is a valid URN as per RFC 2141.
func isUrnRFC2141(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, match := urn.Parse([]byte(value))

	return match
}

// IsFile is the validation function for validating if the current field's value is a valid file path.
func isFile(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	fileInfo, err := os.Stat(value)
	if err != nil {
		return false
	}

	return !fileInfo.IsDir()
}

// IsE164 is the validation function for validating if the current field's value is a valid e.164 formatted phone number.
func isE164(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return E164Regex.MatchString(value)
}

// IsEmail is the validation function for validating if the current field's value is a valid email address.
func isEmail(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return EmailRegex.MatchString(value)
}

// IsHSLA is the validation function for validating if the current field's value is a valid HSLA color.
func isHSLA(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return HslaRegex.MatchString(value)
}

// IsHSL is the validation function for validating if the current field's value is a valid HSL color.
func isHSL(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return HslRegex.MatchString(value)
}

// IsRGBA is the validation function for validating if the current field's value is a valid RGBA color.
func isRGBA(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return RgbaRegex.MatchString(value)
}

// IsRGB is the validation function for validating if the current field's value is a valid RGB color.
func isRGB(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return RgbRegex.MatchString(value)
}

// IsHEXColor is the validation function for validating if the current field's value is a valid HEX color.
func isHEXColor(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return HexcolorRegex.MatchString(value)
}

// IsHexadecimal is the validation function for validating if the current field's value is a valid hexadecimal.
func isHexadecimal(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return HexadecimalRegex.MatchString(value)
}

// IsNumber is the validation function for validating if the current field's value is a valid number.
func isNumber(fieldContext FieldContext) bool {
	switch fieldContext.Value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	default:
		value, ok := fieldContextAsString(fieldContext)
		if !ok {
			return false
		}
		return NumberRegex.MatchString(value)
	}
}

// IsNumeric is the validation function for validating if the current field's value is a valid numeric value.
func isNumeric(fieldContext FieldContext) bool {
	switch fieldContext.Value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, complex64, complex128:
		return true
	default:
		value, ok := fieldContextAsString(fieldContext)
		if !ok {
			return false
		}
		return NumericRegex.MatchString(value)
	}
}

// IsAlphanum is the validation function for validating if the current field's value is a valid alphanumeric value.
func isAlphanum(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return AlphaNumericRegex.MatchString(value)
}

// IsAlpha is the validation function for validating if the current field's value is a valid alpha value.
func isAlpha(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return AlphaRegex.MatchString(value)
}

// IsAlphanumUnicode is the validation function for validating if the current field's value is a valid alphanumeric unicode value.
func isAlphanumUnicode(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return AlphaUnicodeNumericRegex.MatchString(value)
}

// IsAlphaUnicode is the validation function for validating if the current field's value is a valid alpha unicode value.
func isAlphaUnicode(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}
	return AlphaUnicodeRegex.MatchString(value)
}

// isDefault is the opposite of required aka hasValue
func isDefault(fieldContext FieldContext) bool {
	return !hasValue(fieldContext)
}

// HasValue is the validation function for validating if the current field's value is not the default static value.
func hasValue(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if ok {
		return value != ""
	}

	switch fieldValue := fieldContext.Value.(type) {
	case int:
		return fieldValue != 0
	case int8:
		return fieldValue != 0
	case int16:
		return fieldValue != 0
	case int32:
		return fieldValue != 0
	case int64:
		return fieldValue != 0
	case *int:
		return fieldValue != nil && *fieldValue != 0
	case *int8:
		return fieldValue != nil && *fieldValue != 0
	case *int16:
		return fieldValue != nil && *fieldValue != 0
	case *int32:
		return fieldValue != nil && *fieldValue != 0
	case *int64:
		return fieldValue != nil && *fieldValue != 0
	case uint:
		return fieldValue != 0
	case uint8:
		return fieldValue != 0
	case uint16:
		return fieldValue != 0
	case uint32:
		return fieldValue != 0
	case uint64:
		return fieldValue != 0
	case *uint:
		return fieldValue != nil && *fieldValue != 0
	case *uint8:
		return fieldValue != nil && *fieldValue != 0
	case *uint16:
		return fieldValue != nil && *fieldValue != 0
	case *uint32:
		return fieldValue != nil && *fieldValue != 0
	case *uint64:
		return fieldValue != nil && *fieldValue != 0
	case float32:
		return fieldValue != 0
	case float64:
		return fieldValue != 0
	case *float32:
		return fieldValue != nil && *fieldValue != 0
	case *float64:
		return fieldValue != nil && *fieldValue != 0
	case complex64:
		return fieldValue != 0
	case complex128:
		return fieldValue != 0
	case *complex64:
		return fieldValue != nil && *fieldValue != 0
	case *complex128:
		return fieldValue != nil && *fieldValue != 0
	case bool:
		return !fieldValue
	case *bool:
		return fieldValue != nil && !*fieldValue
	default:
		return fieldValue != nil
	}
}

/*
TODO(Jota): To work on this.

// requireCheckField is a func for check field kind
func requireCheckFieldKind(fieldContext FieldContext, param string, defaultNotFoundValue bool) bool {
	field := fl.Field()
	kind := field.Kind()
	var nullable, found bool
	if len(param) > 0 {
		field, kind, nullable, found = fl.GetStructFieldOKAdvanced2(fl.Parent(), param)
		if !found {
			return defaultNotFoundValue
		}
	}
	switch kind {
	case reflect.Invalid:
		return defaultNotFoundValue
	case reflect.Slice, reflect.Map, reflect.Ptr, reflect.Interface, reflect.Chan, reflect.Func:
		return field.IsNil()
	default:
		if nullable && field.Interface() != nil {
			return false
		}
		return field.IsValid() && field.Interface() == reflect.Zero(field.Type()).Interface()
	}
}
*/

/*
TODO(Jota): To work on this.

// requireCheckFieldValue is a func for check field value
func requireCheckFieldValue(fieldContext FieldContext, param string, value string, defaultNotFoundValue bool) bool {
	field, kind, _, found := fl.GetStructFieldOKAdvanced2(fl.Parent(), param)
	if !found {
		return defaultNotFoundValue
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return field.Int() == asInt(value)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint() == asUint(value)

	case reflect.Float32, reflect.Float64:
		return field.Float() == asFloat(value)

	case reflect.Slice, reflect.Map, reflect.Array:
		return int64(field.Len()) == asInt(value)
	}

	// default reflect.String:
	return field.String() == value
}
*/

/*
TODO(Jota): To work on this.

// requiredIf is the validation function
// The field under validation must be present and not empty only if all the other specified fields are equal to the value following with the specified field.
func requiredIf(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	if len(params)%2 != 0 {
		panic(fmt.Sprintf("Bad param number for required_if %s", fl.FieldName()))
	}
	for i := 0; i < len(params); i += 2 {
		if !requireCheckFieldValue(fl, params[i], params[i+1], false) {
			return true
		}
	}
	return hasValue(fl)
}
*/

/*
TODO(Jota): To work on this.

// requiredUnless is the validation function
// The field under validation must be present and not empty only unless all the other specified fields are equal to the value following with the specified field.
func requiredUnless(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	if len(params)%2 != 0 {
		panic(fmt.Sprintf("Bad param number for required_unless %s", fl.FieldName()))
	}

	for i := 0; i < len(params); i += 2 {
		if requireCheckFieldValue(fl, params[i], params[i+1], false) {
			return true
		}
	}
	return hasValue(fl)
}
*/

/*
TODO(Jota): To work on this.

// ExcludedWith is the validation function
// The field under validation must not be present or is empty if any of the other specified fields are present.
func excludedWith(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	for _, param := range params {
		if !requireCheckFieldKind(fl, param, true) {
			return !hasValue(fl)
		}
	}
	return true
}
*/

/*
TODO(Jota): To work on this.

// RequiredWith is the validation function
// The field under validation must be present and not empty only if any of the other specified fields are present.
func requiredWith(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	for _, param := range params {
		if !requireCheckFieldKind(fl, param, true) {
			return hasValue(fl)
		}
	}
	return true
}
*/

/*
TODO(Jota): To work on this.

// ExcludedWithAll is the validation function
// The field under validation must not be present or is empty if all of the other specified fields are present.
func excludedWithAll(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	for _, param := range params {
		if requireCheckFieldKind(fl, param, true) {
			return true
		}
	}
	return !hasValue(fl)
}
*/

/*
TODO(Jota): To work on this.

// RequiredWithAll is the validation function
// The field under validation must be present and not empty only if all of the other specified fields are present.
func requiredWithAll(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	for _, param := range params {
		if requireCheckFieldKind(fl, param, true) {
			return true
		}
	}
	return hasValue(fl)
}
*/

/*
TODO(Jota): To work on this.

// ExcludedWithout is the validation function
// The field under validation must not be present or is empty when any of the other specified fields are not present.
func excludedWithout(fieldContext FieldContext) bool {
	if requireCheckFieldKind(fl, strings.TrimSpace(fl.Param()), true) {
		return !hasValue(fl)
	}
	return true
}
*/

/*
TODO(Jota): To work on this.

// RequiredWithout is the validation function
// The field under validation must be present and not empty only when any of the other specified fields are not present.
func requiredWithout(fieldContext FieldContext) bool {
	if requireCheckFieldKind(fl, strings.TrimSpace(fl.Param()), true) {
		return hasValue(fl)
	}
	return true
}
*/

/*
TODO(Jota): To work on this.

// RequiredWithoutAll is the validation function
// The field under validation must not be present or is empty when all of the other specified fields are not present.
func excludedWithoutAll(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	for _, param := range params {
		if !requireCheckFieldKind(fl, param, true) {
			return true
		}
	}
	return !hasValue(fl)
}
*/

/*
TODO(Jota): To work on this.

// RequiredWithoutAll is the validation function
// The field under validation must be present and not empty only when all of the other specified fields are not present.
func requiredWithoutAll(fieldContext FieldContext) bool {
	params := parseOneOfParam2(fl.Param())
	for _, param := range params {
		if !requireCheckFieldKind(fl, param, true) {
			return true
		}
	}
	return hasValue(fl)
}
*/

/*
TODO(Jota): To work on this.

// IsGteField is the validation function for validating if the current field's value is greater than or equal to the field specified by the param's value.
func isGteField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	currentField, currentKind, ok := fl.GetStructFieldOK()
	if !ok || currentKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:

		return field.Int() >= currentField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:

		return field.Uint() >= currentField.Uint()

	case reflect.Float32, reflect.Float64:

		return field.Float() >= currentField.Float()

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != currentField.Type() {
			return false
		}

		if fieldType == timeType {

			t := currentField.Interface().(time.Time)
			fieldTime := field.Interface().(time.Time)

			return fieldTime.After(t) || fieldTime.Equal(t)
		}
	}

	// default reflect.String
	return len(field.String()) >= len(currentField.String())
}
*/

/*
TODO(Jota): To work on this.

// IsGtField is the validation function for validating if the current field's value is greater than the field specified by the param's value.
func isGtField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	currentField, currentKind, ok := fl.GetStructFieldOK()
	if !ok || currentKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:

		return field.Int() > currentField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:

		return field.Uint() > currentField.Uint()

	case reflect.Float32, reflect.Float64:

		return field.Float() > currentField.Float()

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != currentField.Type() {
			return false
		}

		if fieldType == timeType {

			t := currentField.Interface().(time.Time)
			fieldTime := field.Interface().(time.Time)

			return fieldTime.After(t)
		}
	}

	// default reflect.String
	return len(field.String()) > len(currentField.String())
}
*/

/*
TODO(Jota): To work on this.

// IsGte is the validation function for validating if the current field's value is greater than or equal to the param's value.
func isGte(fieldContext FieldContext) bool {

	field := fl.Field()
	param := fl.Param()

	switch field.Kind() {

	case reflect.String:
		p := asInt(param)

		return int64(utf8.RuneCountInString(field.String())) >= p

	case reflect.Slice, reflect.Map, reflect.Array:
		p := asInt(param)

		return int64(field.Len()) >= p

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p := asIntFromType(field.Type(), param)

		return field.Int() >= p

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		p := asUint(param)

		return field.Uint() >= p

	case reflect.Float32, reflect.Float64:
		p := asFloat(param)

		return field.Float() >= p

	case reflect.Struct:

		if field.Type() == timeType {

			now := time.Now().UTC()
			t := field.Interface().(time.Time)

			return t.After(now) || t.Equal(now)
		}
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
*/

/*
TODO(Jota): To work on this.

// IsGt is the validation function for validating if the current field's value is greater than the param's value.
func isGt(fieldContext FieldContext) bool {

	field := fl.Field()
	param := fl.Param()

	switch field.Kind() {

	case reflect.String:
		p := asInt(param)

		return int64(utf8.RuneCountInString(field.String())) > p

	case reflect.Slice, reflect.Map, reflect.Array:
		p := asInt(param)

		return int64(field.Len()) > p

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p := asIntFromType(field.Type(), param)

		return field.Int() > p

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		p := asUint(param)

		return field.Uint() > p

	case reflect.Float32, reflect.Float64:
		p := asFloat(param)

		return field.Float() > p
	case reflect.Struct:

		if field.Type() == timeType {

			return field.Interface().(time.Time).After(time.Now().UTC())
		}
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
*/

/*
TODO(Jota): To work on this.

// HasLengthOf is the validation function for validating if the current field's value is equal to the param's value.
func hasLengthOf(fieldContext FieldContext) bool {

	field := fl.Field()
	param := fl.Param()

	switch field.Kind() {

	case reflect.String:
		p := asInt(param)

		return int64(utf8.RuneCountInString(field.String())) == p

	case reflect.Slice, reflect.Map, reflect.Array:
		p := asInt(param)

		return int64(field.Len()) == p

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p := asIntFromType(field.Type(), param)

		return field.Int() == p

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		p := asUint(param)

		return field.Uint() == p

	case reflect.Float32, reflect.Float64:
		p := asFloat(param)

		return field.Float() == p
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
*/

/*
TODO(Jota): To work on this.

// HasMinOf is the validation function for validating if the current field's value is greater than or equal to the param's value.
func hasMinOf(fieldContext FieldContext) bool {
	return isGte(fl)
}
*/

/*
TODO(Jota): To work on this.

// IsLteField is the validation function for validating if the current field's value is less than or equal to the field specified by the param's value.
func isLteField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	currentField, currentKind, ok := fl.GetStructFieldOK()
	if !ok || currentKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:

		return field.Int() <= currentField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:

		return field.Uint() <= currentField.Uint()

	case reflect.Float32, reflect.Float64:

		return field.Float() <= currentField.Float()

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != currentField.Type() {
			return false
		}

		if fieldType == timeType {

			t := currentField.Interface().(time.Time)
			fieldTime := field.Interface().(time.Time)

			return fieldTime.Before(t) || fieldTime.Equal(t)
		}
	}

	// default reflect.String
	return len(field.String()) <= len(currentField.String())
}
*/

/*
TODO(Jota): To work on this.

// IsLtField is the validation function for validating if the current field's value is less than the field specified by the param's value.
func isLtField(fieldContext FieldContext) bool {

	field := fl.Field()
	kind := field.Kind()

	currentField, currentKind, ok := fl.GetStructFieldOK()
	if !ok || currentKind != kind {
		return false
	}

	switch kind {

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:

		return field.Int() < currentField.Int()

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:

		return field.Uint() < currentField.Uint()

	case reflect.Float32, reflect.Float64:

		return field.Float() < currentField.Float()

	case reflect.Struct:

		fieldType := field.Type()

		// Not Same underlying type i.e. struct and time
		if fieldType != currentField.Type() {
			return false
		}

		if fieldType == timeType {

			t := currentField.Interface().(time.Time)
			fieldTime := field.Interface().(time.Time)

			return fieldTime.Before(t)
		}
	}

	// default reflect.String
	return len(field.String()) < len(currentField.String())
}
*/

/*
TODO(Jota): To work on this.

// IsLte is the validation function for validating if the current field's value is less than or equal to the param's value.
func isLte(fieldContext FieldContext) bool {

	field := fl.Field()
	param := fl.Param()

	switch field.Kind() {

	case reflect.String:
		p := asInt(param)

		return int64(utf8.RuneCountInString(field.String())) <= p

	case reflect.Slice, reflect.Map, reflect.Array:
		p := asInt(param)

		return int64(field.Len()) <= p

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p := asIntFromType(field.Type(), param)

		return field.Int() <= p

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		p := asUint(param)

		return field.Uint() <= p

	case reflect.Float32, reflect.Float64:
		p := asFloat(param)

		return field.Float() <= p

	case reflect.Struct:

		if field.Type() == timeType {

			now := time.Now().UTC()
			t := field.Interface().(time.Time)

			return t.Before(now) || t.Equal(now)
		}
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
*/

/*
TODO(Jota): To work on this.

// IsLt is the validation function for validating if the current field's value is less than the param's value.
func isLt(fieldContext FieldContext) bool {

	field := fl.Field()
	param := fl.Param()

	switch field.Kind() {

	case reflect.String:
		p := asInt(param)

		return int64(utf8.RuneCountInString(field.String())) < p

	case reflect.Slice, reflect.Map, reflect.Array:
		p := asInt(param)

		return int64(field.Len()) < p

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		p := asIntFromType(field.Type(), param)

		return field.Int() < p

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		p := asUint(param)

		return field.Uint() < p

	case reflect.Float32, reflect.Float64:
		p := asFloat(param)

		return field.Float() < p

	case reflect.Struct:

		if field.Type() == timeType {

			return field.Interface().(time.Time).Before(time.Now().UTC())
		}
	}

	panic(fmt.Sprintf("Bad field type %T", field.Interface()))
}
*/

/*
TODO(Jota): To work on this.

// HasMaxOf is the validation function for validating if the current field's value is less than or equal to the param's value.
func hasMaxOf(fieldContext FieldContext) bool {
	return isLte(fl)
}
*/

// IsTCP4AddrResolvable is the validation function for validating if the field's value is a resolvable tcp4 address.
func isTCP4AddrResolvable(fieldContext FieldContext) bool {

	if !isIP4Addr(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveTCPAddr("tcp4", value)
	return err == nil
}

// IsTCP6AddrResolvable is the validation function for validating if the field's value is a resolvable tcp6 address.
func isTCP6AddrResolvable(fieldContext FieldContext) bool {

	if !isIP6Addr(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveTCPAddr("tcp6", value)

	return err == nil
}

// IsTCPAddrResolvable is the validation function for validating if the field's value is a resolvable tcp address.
func isTCPAddrResolvable(fieldContext FieldContext) bool {

	if !isIP4Addr(fieldContext) && !isIP6Addr(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveTCPAddr("tcp", value)

	return err == nil
}

// IsUDP4AddrResolvable is the validation function for validating if the field's value is a resolvable udp4 address.
func isUDP4AddrResolvable(fieldContext FieldContext) bool {

	if !isIP4Addr(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveUDPAddr("udp4", value)

	return err == nil
}

// IsUDP6AddrResolvable is the validation function for validating if the field's value is a resolvable udp6 address.
func isUDP6AddrResolvable(fieldContext FieldContext) bool {

	if !isIP6Addr(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveUDPAddr("udp6", value)

	return err == nil
}

// IsUDPAddrResolvable is the validation function for validating if the field's value is a resolvable udp address.
func isUDPAddrResolvable(fieldContext FieldContext) bool {

	if !isIP4Addr(fieldContext) && !isIP6Addr(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveUDPAddr("udp", value)

	return err == nil
}

// IsIP4AddrResolvable is the validation function for validating if the field's value is a resolvable ip4 address.
func isIP4AddrResolvable(fieldContext FieldContext) bool {

	if !isIPv4(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveIPAddr("ip4", value)

	return err == nil
}

// IsIP6AddrResolvable is the validation function for validating if the field's value is a resolvable ip6 address.
func isIP6AddrResolvable(fieldContext FieldContext) bool {

	if !isIPv6(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveIPAddr("ip6", value)

	return err == nil
}

// IsIPAddrResolvable is the validation function for validating if the field's value is a resolvable ip address.
func isIPAddrResolvable(fieldContext FieldContext) bool {

	if !isIP(fieldContext) {
		return false
	}

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveIPAddr("ip", value)

	return err == nil
}

// IsUnixAddrResolvable is the validation function for validating if the field's value is a resolvable unix address.
func isUnixAddrResolvable(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	_, err := net.ResolveUnixAddr("unix", value)

	return err == nil
}

func isIP4Addr(fieldContext FieldContext) bool {

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	if idx := strings.LastIndex(value, ":"); idx != -1 {
		value = value[0:idx]
	}

	ip := net.ParseIP(value)

	return ip != nil && ip.To4() != nil
}

func isIP6Addr(fieldContext FieldContext) bool {

	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	if idx := strings.LastIndex(value, ":"); idx != -1 {
		if idx != 0 && value[idx-1:idx] == "]" {
			value = value[1 : idx-1]
		}
	}

	ip := net.ParseIP(value)

	return ip != nil && ip.To4() == nil
}

func isHostnameRFC952(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return HostnameRegexRFC952.MatchString(value)
}

func isHostnameRFC1123(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok {
		return false
	}

	return HostnameRegexRFC1123.MatchString(value)
}

func isFQDN(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	return FqdnRegexRFC1123.MatchString(value)
}

// IsDir is the validation function for validating if the current field's value is a valid directory.
func isDir(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	fileInfo, err := os.Stat(value)
	if err != nil {
		return false
	}

	return fileInfo.IsDir()
}

// isJSON is the validation function for validating if the current field's value is a valid json string.
func isJSON(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	return json.Valid([]byte(value))
}

// isHostnamePort validates a <dns>:<port> combination for fields typically used for socket address.
func isHostnamePort(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	// Port must be a iny <= 65535.
	if portNum, err := strconv.ParseInt(port, 10, 32); err != nil || portNum > 65535 || portNum < 1 {
		return false
	}

	// If host is specified, it should match a DNS name
	if host != "" {
		return HostnameRegexRFC1123.MatchString(host)
	}
	return true
}

// isLowercase is the validation function for validating if the current field's value is a lowercase string.
func isLowercase(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	if value == "" {
		return false
	}
	return value == strings.ToLower(value)
}

// isUppercase is the validation function for validating if the current field's value is an uppercase string.
func isUppercase(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	if value == "" {
		return false
	}
	return value == strings.ToUpper(value)
}

// isDatetime is the validation function for validating if the current field's value is a valid datetime string.
func isDatetime(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	if len(fieldContext.Params) == 0 {
		return false
	}

	for _, param := range fieldContext.Params {
		_, err := time.Parse(param, value)

		if err == nil {
			return true
		}
	}
	return false
}

// isTimeZone is the validation function for validating if the current field's value is a valid time zone string.
func isTimeZone(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}

	// Local value is converted to the current system time zone by time.LoadLocation but disallow it as it is not a valid time zone name
	if strings.ToLower(value) == "local" {
		return false
	}

	_, err := time.LoadLocation(value)
	if err != nil {
		return false
	}

	return true
}

// isIso3166Alpha2 is the validation function for validating if the current field's value is a valid iso3166-1 alpha-2 country code.
func isIso3166Alpha2(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}
	return iso3166_1_alpha2[value]
}

// isIso3166Alpha2 is the validation function for validating if the current field's value is a valid iso3166-1 alpha-3 country code.
func isIso3166Alpha3(fieldContext FieldContext) bool {
	value, ok := fieldContextAsString(fieldContext)
	if !ok || value == "" {
		return false
	}
	return iso3166_1_alpha3[value]
}

// isIso3166Alpha2 is the validation function for validating if the current field's value is a valid iso3166-1 alpha-numeric country code.
func isIso3166AlphaNumeric(fieldContext FieldContext) bool {
	var code int
	switch fieldValue := fieldContext.Value.(type) {
	case int:
		code = int(fieldValue % 1000)
	case int8:
		code = int(fieldValue)
	case int16:
		code = int(fieldValue % 1000)
	case int32:
		code = int(fieldValue % 1000)
	case int64:
		code = int(fieldValue % 1000)
	case uint:
		code = int(fieldValue % 1000)
	case uint8:
		code = int(fieldValue)
	case uint16:
		code = int(fieldValue % 1000)
	case uint32:
		code = int(fieldValue % 1000)
	case uint64:
		code = int(fieldValue % 1000)
	default:
		// panic(fmt.Sprintf("Bad field type %T", field.Interface()))
		return false
	}
	return iso3166_1_alpha_numeric[code]
}
