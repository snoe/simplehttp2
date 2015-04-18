package main
import (
  "fmt"
  "flag"
  "log"
  "net"
  "net/http"
  "crypto/tls"

  "github.com/bradfitz/http2"
)

var (
  certPEMBlock = []byte(`-----BEGIN CERTIFICATE-----
MIIDPjCCAiYCCQDizia/MoUFnDANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJV
UzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xFDASBgNVBAoT
C0JyYWRmaXR6aW5jMRIwEAYDVQQDEwlsb2NhbGhvc3QxHTAbBgkqhkiG9w0BCQEW
DmJyYWRAZGFuZ2EuY29tMB4XDTE0MDcxNTIwNTAyN1oXDTE1MTEyNzIwNTAyN1ow
RzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQswCQYDVQQHEwJTRjEeMBwGA1UE
ChMVYnJhZGZpdHogaHR0cDIgc2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAs1Y9CyLFrdL8VQWN1WaifDqaZFnoqjHhCMlc1TfG2zA+InDifx2l
gZD3o8FeNnAcfM2sPlk3+ZleOYw9P/CklFVDlvqmpCv9ss/BEp/dDaWvy1LmJ4c2
dbQJfmTxn7CV1H3TsVJvKdwFmdoABb41NoBp6+NNO7OtDyhbIMiCI0pL3Nefb3HL
A7hIMo3DYbORTtJLTIH9W8YKrEWL0lwHLrYFx/UdutZnv+HjdmO6vCN4na55mjws
/vjKQUmc7xeY7Xe20xDEG2oDKVkL2eD7FfyrYMS3rO1ExP2KSqlXYG/1S9I/fz88
F0GK7HX55b5WjZCl2J3ERVdnv/0MQv+sYQIDAQABMA0GCSqGSIb3DQEBBQUAA4IB
AQC0zL+n/YpRZOdulSu9tS8FxrstXqGWoxfe+vIUgqfMZ5+0MkjJ/vW0FqlLDl2R
rn4XaR3e7FmWkwdDVbq/UB6lPmoAaFkCgh9/5oapMaclNVNnfF3fjCJfRr+qj/iD
EmJStTIN0ZuUjAlpiACmfnpEU55PafT5Zx+i1yE4FGjw8bJpFoyD4Hnm54nGjX19
KeCuvcYFUPnBm3lcL0FalF2AjqV02WTHYNQk7YF/oeO7NKBoEgvGvKG3x+xaOeBI
dwvdq175ZsGul30h+QjrRlXhH/twcuaT3GSdoysDl9cCYE8f1Mk8PD6gan3uBCJU
90p6/CbU71bGbfpM2PHot2fm
-----END CERTIFICATE-----`)

  keyPEMBlock = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAs1Y9CyLFrdL8VQWN1WaifDqaZFnoqjHhCMlc1TfG2zA+InDi
fx2lgZD3o8FeNnAcfM2sPlk3+ZleOYw9P/CklFVDlvqmpCv9ss/BEp/dDaWvy1Lm
J4c2dbQJfmTxn7CV1H3TsVJvKdwFmdoABb41NoBp6+NNO7OtDyhbIMiCI0pL3Nef
b3HLA7hIMo3DYbORTtJLTIH9W8YKrEWL0lwHLrYFx/UdutZnv+HjdmO6vCN4na55
mjws/vjKQUmc7xeY7Xe20xDEG2oDKVkL2eD7FfyrYMS3rO1ExP2KSqlXYG/1S9I/
fz88F0GK7HX55b5WjZCl2J3ERVdnv/0MQv+sYQIDAQABAoIBADQ2spUwbY+bcz4p
3M66ECrNQTBggP40gYl2XyHxGGOu2xhZ94f9ELf1hjRWU2DUKWco1rJcdZClV6q3
qwmXvcM2Q/SMS8JW0ImkNVl/0/NqPxGatEnj8zY30d/L8hGFb0orzFu/XYA5gCP4
NbN2WrXgk3ZLeqwcNxHHtSiJWGJ/fPyeDWAu/apy75u9Xf2GlzBZmV6HYD9EfK80
LTlI60f5FO487CrJnboL7ovPJrIHn+k05xRQqwma4orpz932rTXnTjs9Lg6KtbQN
a7PrqfAntIISgr11a66Mng3IYH1lYqJsWJJwX/xHT4WLEy0EH4/0+PfYemJekz2+
Co62drECgYEA6O9zVJZXrLSDsIi54cfxA7nEZWm5CAtkYWeAHa4EJ+IlZ7gIf9sL
W8oFcEfFGpvwVqWZ+AsQ70dsjXAv3zXaG0tmg9FtqWp7pzRSMPidifZcQwWkKeTO
gJnFmnVyed8h6GfjTEu4gxo1/S5U0V+mYSha01z5NTnN6ltKx1Or3b0CgYEAxRgm
S30nZxnyg/V7ys61AZhst1DG2tkZXEMcA7dYhabMoXPJAP/EfhlWwpWYYUs/u0gS
Wwmf5IivX5TlYScgmkvb/NYz0u4ZmOXkLTnLPtdKKFXhjXJcHjUP67jYmOxNlJLp
V4vLRnFxTpffAV+OszzRxsXX6fvruwZBANYJeXUCgYBVouLFsFgfWGYp2rpr9XP4
KK25kvrBqF6JKOIDB1zjxNJ3pUMKrl8oqccCFoCyXa4oTM2kUX0yWxHfleUjrMq4
yimwQKiOZmV7fVLSSjSw6e/VfBd0h3gb82ygcplZkN0IclkwTY5SNKqwn/3y07V5
drqdhkrgdJXtmQ6O5YYECQKBgATERcDToQ1USlI4sKrB/wyv1AlG8dg/IebiVJ4e
ZAyvcQmClFzq0qS+FiQUnB/WQw9TeeYrwGs1hxBHuJh16srwhLyDrbMvQP06qh8R
48F8UXXSRec22dV9MQphaROhu2qZdv1AC0WD3tqov6L33aqmEOi+xi8JgbT/PLk5
c/c1AoGBAI1A/02ryksW6/wc7/6SP2M2rTy4m1sD/GnrTc67EHnRcVBdKO6qH2RY
nqC8YcveC2ZghgPTDsA3VGuzuBXpwY6wTyV99q6jxQJ6/xcrD9/NUG6Uwv/xfCxl
IJLeBYEqQundSSny3VtaAUK8Ul1nxpTvVRNwtcyWTo8RHAAyNPWd
-----END RSA PRIVATE KEY-----`)
  addr = flag.String("addr", "localhost:4430", "TLS address to listen on")
  httpaddr = flag.String("httpaddr", "localhost:8080", "HTTP address to listen on")
)

type tcpKeepAliveListener struct {
  *net.TCPListener
}

func ListenAndServeTLS(srv *http.Server, certPEMBlock, keyPEMBlock []byte) error {
  config := &tls.Config{}
  if srv.TLSConfig != nil {
    *config = *srv.TLSConfig
  }

  var err error
  config.Certificates = make([]tls.Certificate, 1)
  config.Certificates[0], err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)

  if err != nil {
    return err
  }
  ln, err := net.Listen("tcp", *addr)
  if err != nil {
    return err
  }

  tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
  return srv.Serve(tlsListener)
}

func main() {

  fmt.Println("Serving files in the current directory on https://localhost:4430/ and http://localhost:80/")
  http.Handle("/", http.FileServer(http.Dir(".")))

  var srv http.Server
  srv.Addr = *addr
  http2.ConfigureServer(&srv, &http2.Server{})

  go func() {
    log.Fatal(http.ListenAndServe(*httpaddr, nil))
  }()

  go func() {
    log.Fatal(ListenAndServeTLS(&srv, certPEMBlock, keyPEMBlock))
  }()

  select {}
}
