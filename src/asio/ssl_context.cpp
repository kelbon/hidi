#include "hidi/asio/ssl_context.hpp"
#include "hidi/errors.hpp"
#include "hidi/logger.hpp"

#include <filesystem>

#ifdef HIDI_DEBUG_SSL_KEYS_FILE
  #include <fstream>
  #include <iostream>
#endif

namespace hidi {

ssl_context::ssl_context(asio::ssl::context_base::method m) : ctx(m) {
}

#ifdef HIDI_DEBUG_SSL_KEYS_FILE

static void keylog_callback(const SSL*, const char* line) {
  std::filesystem::path keylog_file_path = HIDI_DEBUG_SSL_KEYS_FILE;
  std::ofstream keylog_file(keylog_file_path, std::ios_base::app | std::ios_base::out);
  if (keylog_file)
    keylog_file << std::string_view(line) << std::endl;
  else
    std::cout << std::format("cannot open keylog file for wireshark debug keys storing, path: {}",
                             keylog_file_path.string())
              << std::endl;
}

#endif

static ssl_context_ptr make_ssl_context_for_http11(std::span<const std::filesystem::path> additional_certs,
                                                   const log_context& logctx) {
  namespace ssl = asio::ssl;
  asio::ssl::context_base::method method =
#ifndef HIDI_DEBUG_SSL_KEYS_FILE
      ssl::context::tlsv13_client;
#else
      ssl::context::tlsv12_client;
#endif

  ssl_context_ptr sslctx = new ssl_context(method);
#ifdef HIDI_DEBUG_SSL_KEYS_FILE
  HTTP2_LOG(logctx, WARN, "SSL debug keys store enabled, file path: {}", HIDI_DEBUG_SSL_KEYS_FILE);
  SSL_CTX_set_keylog_callback(sslctx->ctx.native_handle(), &keylog_callback);
#endif
  sslctx->ctx.set_default_verify_paths();

  for (io_error_code ec; const auto& p : additional_certs) {
    std::filesystem::path ap = std::filesystem::absolute(p);
    ec = sslctx->ctx.load_verify_file(ap.string(), ec);
    if (ec)
      HTTP2_LOG(logctx, ERROR, "error while loading ssl verify file, err: {}, path: {}", ec.message(),
                p.string());
    else
      HTTP2_LOG(logctx, INFO, "additional SSL certificate loaded, path: {}", p.string());
  }

  sslctx->ctx.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 |
                          ssl::context::no_sslv3 | ssl::context::single_dh_use |
                          ssl::context::no_compression | ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1);

  if (!SSL_CTX_set_cipher_list(sslctx->ctx.native_handle(),
                               "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:DEFAULT"))
    HTTP2_LOG(logctx, WARN, "ssl cipher cannot be selected");

  return sslctx;
}

client_ssl_context_ptr make_ssl_context_for_client(std::span<const std::filesystem::path> additional_certs,
                                                   const log_context& logctx) {
  ssl_context_ptr sslctx = make_ssl_context_for_http11(additional_certs, logctx);
  const unsigned char alpn_protos[] = {0x02, 'h', '2'};  // HTTP/2
  if (0 != SSL_CTX_set_alpn_protos(sslctx->ctx.native_handle(), alpn_protos, sizeof(alpn_protos)))
    throw network_exception{"ALPN ctx broken {}", ERR_error_string(ERR_get_error(), nullptr)};
  return client_ssl_context_ptr{std::move(sslctx)};
}

// https://www.rfc-editor.org/rfc/rfc9113.html#section-3.2
// выбирает h2, если клиент его предлагает. Иначе ALPN просто не согласуется, соединение не отклоняется
static int select_h2(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in,
                     unsigned int inlen, void*) {
  static const unsigned char h2[] = {0x02, 'h', '2'};
  unsigned char* selected = nullptr;
  if (SSL_select_next_proto(&selected, outlen, h2, sizeof(h2), in, inlen) != OPENSSL_NPN_NEGOTIATED)
    return SSL_TLSEXT_ERR_NOACK;
  *out = selected;
  return SSL_TLSEXT_ERR_OK;
}

server_ssl_context_ptr make_ssl_context_for_server(std::filesystem::path certificate,
                                                   std::filesystem::path server_private_key,
                                                   const log_context& logctx) {
  ssl_context_ptr ctx = new ssl_context(asio::ssl::context_base::tls_server);
  // https://www.rfc-editor.org/rfc/rfc9113.html#section-9.2 HTTP/2 требует TLS 1.2 или новее
  ctx->ctx.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 |
                       boost::asio::ssl::context::no_sslv3 | boost::asio::ssl::context::single_dh_use |
                       boost::asio::ssl::context::no_compression | boost::asio::ssl::context::no_tlsv1 |
                       boost::asio::ssl::context::no_tlsv1_1);

  io_error_code ec;
  ec = ctx->ctx.use_certificate_chain_file(std::filesystem::absolute(certificate).string(), ec);
  if (ec) {
    HTTP2_LOG(logctx, ERROR, "cannot load server certificate, path {}, err: {}", certificate.string(),
              ec.message());
    throw network_exception("cannot load server certificate, path {}, err: {}", certificate.string(),
                            ec.message());
  }
  ec = ctx->ctx.use_private_key_file(std::filesystem::absolute(server_private_key).string(),
                                     asio::ssl::context::pem, ec);
  if (ec) {
    HTTP2_LOG(logctx, ERROR, "cannot load server private key file, path {}, err: {}",
              server_private_key.string(), ec.message());
    throw network_exception("cannot load server private key file, path {}, err: {}",
                            server_private_key.string(), ec.message());
  }
  SSL_CTX_set_alpn_select_cb(ctx->ctx.native_handle(), &select_h2, nullptr);
  return server_ssl_context_ptr{std::move(ctx)};
}

}  // namespace hidi
