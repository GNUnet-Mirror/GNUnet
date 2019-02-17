class Gnunet < Formula
  desc "GNUnet"
  homepage "https://gnunet.org/"
  #url "http://ftpmirror.gnu.org/gnunet/gnunet-0.11.0pre66.tar.gz"
  head do
    url "https://gnunet.org/git/gnunet.git"
    depends_on "automake"
  end
  mirror "http://ftpmirror.gnu.org/gnunet/gnunet-0.11.0pre66.tar.gz"
  sha256 "07ed1e456c0cc982fe4c6d335eb2fd41820eb24dcf1c9abc93dad868aa72edbf"

  #bottle do
  #  cellar :any
  #  sha256 "7507da89370f72be8fb22d1932524295231904a2a180ff0bfc4a14d3bd496e31" => :mojave
  #  sha256 "3bdf1fbe152231ba3a9cd19445c242cfb14140fa942a1df03af5c69754e09225" => :high_sierra
  #  sha256 "6dec32c6b29e69d051edd1220bc040cb01911cd20220687dd09bf6e76317b42a" => :sierra
  #end

  depends_on "pkg-config" => :build
  depends_on "glpk"
  depends_on "gettext"
  depends_on "gnutls"
  depends_on "jansson"
  depends_on "libextractor"
  depends_on "libgcrypt"
  depends_on "libffi"
  depends_on "libidn2"
  depends_on "libmicrohttpd"
  depends_on "libmpc"
  depends_on "libunistring"
  depends_on "unbound"

  def install
    args = %W[
      --disable-documentation
      --prefix=#{prefix}
    ]

    system "./bootstrap" if build.head?
    system "./configure", *args
    system "make", "install"
  end

  test do
    system bin/"gnutls-arm", "--version"
  end
end
