require 'uri'
require 'socket'
require 'openssl'
require 'forwardable'

module Houston
  class Connection
    extend Forwardable
    def_delegators :@ssl, :read, :write
    def_delegators :@uri, :scheme, :host, :port

    attr_reader :ssl, :socket, :certificate, :passphrase

    class << self
      def open(uri, certificate, passphrase, certificate_pkey)
        return unless block_given?

        connection = new(uri, certificate, passphrase, certificate_pkey)
        connection.open

        yield connection

        connection.close
      end
    end

    def initialize(uri, certificate, passphrase, certificate_pkey)
      @uri              = URI(uri)
      @certificate      = certificate.to_s
      @certificate_pkey = certificate_pkey.to_s
      @passphrase       = passphrase.to_s unless passphrase.nil?
    end

    def open
      return false if open?

      @socket = TCPSocket.new(@uri.host, @uri.port)

      context = OpenSSL::SSL::SSLContext.new
      # pass `extracted_private_key` to RSA.new
      context.key = OpenSSL::PKey::RSA.new(@certificate_pkey, @passphrase)
      # pass file-dump to X509
      context.cert = OpenSSL::X509::Certificate.new(@certificate)

      @ssl = OpenSSL::SSL::SSLSocket.new(@socket, context)
      @ssl.sync = true
      @ssl.connect
    end

    def open?
      !(@ssl && @socket).nil?
    end

    def close
      return false if closed?

      @ssl.close
      @ssl = nil

      @socket.close
      @socket = nil
    end

    def closed?
      !open?
    end
  end
end
