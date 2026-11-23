package identitytest

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// TC-988-22 (geekdojo/geekdojo-brain#988): the walk's decodeQR reads TOTP
// codes shaped as Keycloak 26.8.2 renders them (ZXing QRCodeWriter, 246x246,
// default hints) and the theme embeds them (data:image/png;base64, with a
// space after the comma). The three secrets below are clean renders that the
// default finder-pattern detector cannot locate, in Java ZXing 3.4.0 and in
// gozxing alike, so a reader without the PURE_BARCODE hint fails on them.
func TestThemeWalk_DecodeQR(t *testing.T) {
	const pre = "otpauth://totp/Hoodoo%20Home:walk-hoodoo?secret="
	const post = "&digits=6&algorithm=SHA1&issuer=Hoodoo%20Home&period=30"
	for _, secret := range []string{
		"NZ4VORLOMVHE4MLIG5DHEN2PJFXTM6CB",
		"IJ3HU4LXNZGHCMD2NVTE4NCMNZ4VC3CY",
		"GFZW6MZWORKFIMKHNFEXAMC2JFKDM2LP",
	} {
		uri := pre + secret + post
		t.Run(secret, func(t *testing.T) {
			bm, err := qrcode.NewQRCodeWriter().Encode(uri, gozxing.BarcodeFormat_QR_CODE, 246, 246, nil)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			var buf bytes.Buffer
			if err := png.Encode(&buf, bm); err != nil {
				t.Fatalf("png: %v", err)
			}
			got, err := decodeQR("data:image/png;base64, " + base64.StdEncoding.EncodeToString(buf.Bytes()))
			if err != nil {
				t.Fatalf("decodeQR: %v", err)
			}
			if got != uri {
				t.Fatalf("decodeQR = %q, want %q", got, uri)
			}
		})
	}
}
