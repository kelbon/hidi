
// tls_connection против TLS сокета boost asio (asio::ssl::stream): две независимые реализации записи и
// чтения TLS поверх одной TLS библиотеки должны понимать друг друга в обе стороны на любых данных и одинаково
// сообщать о закрытии соединения

#include "test_connection.hpp"
#include "hidi/asio/io_impl.hpp"
#include "hidi/buffered_connection.hpp"

#include <boost/asio/ssl.hpp>

#include <moko3/moko3.hpp>

#include <optional>
#include <random>
#include <vector>

using namespace hidi;

namespace {

namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using asio_tls_stream = ssl::stream<tcp::socket>;

// маленькие буферы сокетов: запись упирается в заполненный сокет посреди записи
// Но не меньше нескольких TCP сегментов. С буфером в пару килобайт окно приёма TCP сравнимо с одним
// сегментом, и стоит получателю оценить размер сегмента чуть меньше, чем у отправителя, как объявленное им
// окно (кратное этой оценке) перестаёт вмещать сегмент отправителя. Тогда данные идут только по таймеру
// проб окна, сотни байт в секунду, и тест не укладывается в таймаут
constexpr int SMALL_SOCKET_BUFFER = 16 * 1024;

// вариант пары соединений
struct setup {
  // tls_connection - клиент, сокет asio - сервер, или наоборот
  bool our_client = true;
  // версия TLS, на которую согласен сокет asio. Клиент библиотеки (make_ssl_context_for_client) согласен
  // только на TLS 1.3, сервер и на 1.2
  int peer_version = TLS1_3_VERSION;
  // tls_connection под buffered_connection, как его создаёт библиотека, или сам по себе
  bool buffered = true;
  bool small_socket_buffers = false;
  // для тестов с одним направлением данных: пишет tls_connection, читает сокет asio, или наоборот
  bool to_asio = true;
};

// все варианты, в которых handshake успешен
std::vector<setup> all_setups() {
  std::vector<setup> result;
  for (bool buffered : {true, false}) {
    for (bool small_socket_buffers : {false, true}) {
      result.push_back({true, TLS1_3_VERSION, buffered, small_socket_buffers});
      result.push_back({false, TLS1_3_VERSION, buffered, small_socket_buffers});
      result.push_back({false, TLS1_2_VERSION, buffered, small_socket_buffers});
    }
  }
  return result;
}

// то же для каждого направления данных
std::vector<setup> all_setups_and_directions() {
  std::vector<setup> result;
  for (setup s : all_setups()) {
    for (bool to_asio : {true, false}) {
      s.to_asio = to_asio;
      result.push_back(s);
    }
  }
  return result;
}

// задача, которая выполняется одновременно с телом теста
struct background {
  bool done = false;
  std::exception_ptr ex;

  dd::job run(dd::task<void> t) {
    try {
      co_await t;
    } catch (...) {
      ex = std::current_exception();
    }
    done = true;
  }

  // ждёт завершения, исключение задачи (например от REQUIRE) становится исключением теста
  dd::task<void> join(any_io_context& io) {
    co_await wait_until([&] { return done; }, *&io, deadline_after(60s));
    if (ex)
      std::rethrow_exception(ex);
  }
};

// tls_connection и сокет asio на двух концах одного TCP соединения
struct tls_pair {
  any_io_context ioctx;
  any_connection_t ours;
  // контекст сокета asio: клиентский свой, серверный - как у серверов библиотеки (с тестовым сертификатом)
  std::optional<ssl::context> peer_client_ctx;
  ssl_context_ptr peer_server_ctx;
  std::optional<asio_tls_stream> peer;

  tls_pair(boost::asio::io_context& rawio, const setup& s) : ioctx(make_asio_io_context(rawio)) {
    tcp::acceptor a(rawio, localhost());
    tcp::socket client(rawio);
    client.open(a.local_endpoint().protocol());
    if (s.small_socket_buffers) {
      // принятые соединения наследуют размер буфера от слушающего сокета
      a.set_option(boost::asio::socket_base::receive_buffer_size(SMALL_SOCKET_BUFFER));
      a.set_option(boost::asio::socket_base::send_buffer_size(SMALL_SOCKET_BUFFER));
      client.set_option(boost::asio::socket_base::receive_buffer_size(SMALL_SOCKET_BUFFER));
      client.set_option(boost::asio::socket_base::send_buffer_size(SMALL_SOCKET_BUFFER));
    }
    a.listen();
    // соединение попадает в очередь listen раньше accept
    client.connect(a.local_endpoint());
    tcp::socket server = a.accept();
    // как у соединений библиотеки: иначе мелкие записи ждут подтверждения предыдущих (алгоритм Нейгла)
    client.set_option(tcp::no_delay(true));
    server.set_option(tcp::no_delay(true));

    tcp::socket& our_sock = s.our_client ? client : server;
    tcp::socket& peer_sock = s.our_client ? server : client;
    ssl_context_ptr our_ctx = s.our_client ? make_ssl_context_for_client({}).p : test_server_ssl_ctx().p;
    if (s.buffered) {
      ours.emplace<buffered_connection<tls_connection>>(*&ioctx, 64 * 1024, std::move(our_sock),
                                                        std::move(our_ctx));
    } else {
      ours.emplace<tls_connection>(std::move(our_sock), std::move(our_ctx));
    }

    // версия задаётся контексту до создания сокета: сокет копирует настройки контекста
    if (s.our_client) {
      peer_server_ctx = test_server_ssl_ctx().p;
      set_version(peer_server_ctx->ctx, s.peer_version);
      peer.emplace(std::move(peer_sock), peer_server_ctx->ctx);
    } else {
      peer_client_ctx.emplace(ssl::context::tls_client);
      peer_client_ctx->set_verify_mode(ssl::verify_none);
      const unsigned char alpn[] = {2, 'h', '2'};
      REQUIRE(0 == SSL_CTX_set_alpn_protos(peer_client_ctx->native_handle(), alpn, sizeof(alpn)));
      set_version(*peer_client_ctx, s.peer_version);
      peer.emplace(std::move(peer_sock), *peer_client_ctx);
    }
  }

  static void set_version(ssl::context& ctx, int version) {
    REQUIRE(SSL_CTX_set_min_proto_version(ctx.native_handle(), version));
    REQUIRE(SSL_CTX_set_max_proto_version(ctx.native_handle(), version));
  }

  SSL* our_ssl() {
    if (auto* b = aa::any_cast<buffered_connection<tls_connection>>(&ours))
      return b->inner.session.native_handle();
    return aa::any_cast<tls_connection&>(ours).session.native_handle();
  }

  dd::task<void> peer_handshake(bool is_client, io_error_code& ec) {
    co_await net.handshake(*peer, is_client ? ssl::stream_base::client : ssl::stream_base::server, ec);
  }

  // handshake обеих сторон одновременно
  dd::task<void> handshake(const setup& s, io_error_code& our_ec, io_error_code& peer_ec) {
    background peer_side;
    (void)peer_side.run(peer_handshake(/*is_client=*/!s.our_client, peer_ec));
    co_await ours.handshake(our_ec, s.our_client);
    co_await peer_side.join(ioctx);
  }

  dd::task<void> handshake(const setup& s) {
    io_error_code our_ec;
    io_error_code peer_ec;
    co_await handshake(s, our_ec, peer_ec);
    REQUIRE(!our_ec);
    REQUIRE(!peer_ec);
  }

  // close_notify от сокета asio. Завершается, когда пир ответит своим close_notify или закроет соединение
  dd::task<void> peer_close_notify(io_error_code& ec) {
    co_await dd::this_coro::suspend_and([&](std::coroutine_handle<> h) {
      peer->async_shutdown([&ec, h](const io_error_code& e) {
        ec = e;
        h.resume();
      });
    });
  }
};

// один из концов пары: обе реализации за одним интерфейсом, чтобы один и тот же сценарий шёл в обе стороны
struct side {
  any_connection_t* ours = nullptr;
  asio_tls_stream* peer = nullptr;

  // пишет всё
  dd::task<void> write(std::span<const byte_t> bytes, io_error_code& ec) {
    if (ours)
      co_await write_awaiter(*ours, ec, bytes);
    else
      co_await net.write(*peer, bytes, ec);
  }

  // читает ровно bytes.size()
  dd::task<void> read(std::span<byte_t> bytes, io_error_code& ec) {
    if (ours)
      co_await read_awaiter(*ours, ec, bytes);
    else
      co_await net.read(*peer, bytes, ec);
  }
};

side our_side(tls_pair& p) {
  return side{.ours = std::addressof(p.ours)};
}

side peer_side(tls_pair& p) {
  return side{.peer = &*p.peer};
}

std::vector<byte_t> random_bytes(size_t n, std::mt19937_64& rng) {
  std::vector<byte_t> r(n);
  for (byte_t& b : r)
    b = byte_t(rng());
  return r;
}

// размер следующего куска: до `max_chunk` байт, но не больше оставшегося
size_t next_chunk(size_t left, size_t max_chunk, std::mt19937_64& rng) {
  return std::min<size_t>(left, 1 + rng() % max_chunk);
}

// пишет `data` кусками случайного размера
dd::task<void> write_chunked(side to, std::span<const byte_t> data, size_t max_chunk, size_t seed) {
  std::mt19937_64 rng(seed);
  while (!data.empty()) {
    size_t n = next_chunk(data.size(), max_chunk, rng);
    io_error_code ec;
    co_await to.write(data.first(n), ec);
    REQUIRE(!ec);
    data = data.subspan(n);
  }
}

// читает кусками случайного размера, пока не заполнит `out`
dd::task<void> read_chunked(side from, std::span<byte_t> out, size_t max_chunk, size_t seed) {
  std::mt19937_64 rng(seed);
  while (!out.empty()) {
    size_t n = next_chunk(out.size(), max_chunk, rng);
    io_error_code ec;
    co_await from.read(out.first(n), ec);
    REQUIRE(!ec);
    out = out.subspan(n);
  }
}

// `from` пишет `size` случайных байт, `to` одновременно читает их. Размеры кусков записи и чтения случайны и
// не связаны друг с другом
dd::task<void> transfer(tls_pair& p, side from, side to, size_t size, size_t max_write_chunk,
                        size_t max_read_chunk, size_t seed) {
  std::mt19937_64 rng(seed);
  std::vector<byte_t> data = random_bytes(size, rng);
  std::vector<byte_t> received(size);
  background writer;
  (void)writer.run(write_chunked(from, data, max_write_chunk, rng()));
  co_await read_chunked(to, received, max_read_chunk, rng());
  co_await writer.join(p.ioctx);
  REQUIRE((received == data));
}

std::string_view alpn_selected(SSL* s) {
  const unsigned char* selected = nullptr;
  unsigned int len = 0;
  SSL_get0_alpn_selected(s, &selected, &len);
  return std::string_view((const char*)selected, len);
}

}  // namespace

// обе стороны согласуют одну версию TLS и h2 в ALPN, после handshake сразу обмениваются данными
TRANSPORT_TEST("tls_connection handshake with asio TLS socket") {
  const setup s = GENERATE_RANGE(all_setups());
  tls_pair p(rawio, s);
  co_await p.handshake(s);

  REQUIRE_EQ(SSL_version(p.our_ssl()), s.peer_version);
  REQUIRE_EQ(SSL_version(p.peer->native_handle()), s.peer_version);
  REQUIRE_EQ(alpn_selected(p.our_ssl()), std::string_view("h2"));
  REQUIRE_EQ(alpn_selected(p.peer->native_handle()), std::string_view("h2"));

  // первые данные обеих сторон идут навстречу друг другу (у сервера TLS 1.3 перед ними ещё NewSessionTicket)
  std::vector<byte_t> hello_ours = {'o', 'u', 'r', 's'};
  std::vector<byte_t> hello_peer = {'p', 'e', 'e', 'r', '!'};
  io_error_code ec;
  co_await our_side(p).write(hello_ours, ec);
  REQUIRE(!ec);
  co_await peer_side(p).write(hello_peer, ec);
  REQUIRE(!ec);
  std::vector<byte_t> got_from_peer(hello_peer.size());
  co_await our_side(p).read(got_from_peer, ec);
  REQUIRE(!ec);
  REQUIRE((got_from_peer == hello_peer));
  std::vector<byte_t> got_from_ours(hello_ours.size());
  co_await peer_side(p).read(got_from_ours, ec);
  REQUIRE(!ec);
  REQUIRE((got_from_ours == hello_ours));
}

// стороны не согласны в версии TLS: handshake завершается ошибкой у обеих, а не зависает. Отказавшая сторона
// сообщает причину алертом: другая получает ошибку TLS, а не обрыв соединения
TRANSPORT_TEST("tls_connection handshake fails on TLS version mismatch") {
  setup s{.buffered = GENERATE(true, false)};
  SECTION("asio server refuses") {
    // клиент библиотеки согласен только на TLS 1.3
    s.our_client = true;
    s.peer_version = TLS1_2_VERSION;
  }
  SECTION("tls_connection server refuses") {
    // сервер библиотеки согласен на TLS 1.2 и новее
    s.our_client = false;
    s.peer_version = TLS1_1_VERSION;
  }
  tls_pair p(rawio, s);
  io_error_code our_ec;
  io_error_code peer_ec;
  co_await p.handshake(s, our_ec, peer_ec);
  REQUIRE(our_ec.category() == boost::asio::error::get_ssl_category());
  REQUIRE(peer_ec.category() == boost::asio::error::get_ssl_category());
  co_await p.ours.shutdown();
}

// клиент отправляет первые данные одним куском с последним сообщением handshake (TLS 1.3 это разрешает).
// Сервер получает их тем же чтением из сокета, которым завершает handshake, и должен отдать читателю,
// хотя из сокета больше ничего не придёт
TRANSPORT_TEST("tls_connection server reads data received with the end of handshake") {
  struct variant {
    bool buffered;
    size_t size;
  };
  const variant v = GENERATE(variant{true, 1}, variant{false, 1}, variant{true, 5000}, variant{false, 5000},
                             variant{true, 100'000}, variant{false, 100'000});
  // сторона asio здесь не нужна: клиент - tls_session поверх TCP сокета, чтобы управлять тем, что уходит
  // одной записью в сокет
  any_io_context ioctx = make_asio_io_context(rawio);
  tcp::acceptor a(rawio, localhost());
  a.listen();
  tcp::socket client_sock(rawio);
  client_sock.connect(a.local_endpoint());
  any_connection_t server;
  if (v.buffered) {
    server.emplace<buffered_connection<tls_connection>>(*&ioctx, 64 * 1024, a.accept(),
                                                        test_server_ssl_ctx().p);
  } else {
    server.emplace<tls_connection>(a.accept(), test_server_ssl_ctx().p);
  }
  std::mt19937_64 rng(v.size);
  const std::vector<byte_t> data = random_bytes(v.size, rng);

  ssl_context_ptr client_ctx = make_ssl_context_for_client({}).p;
  tls_session client(client_ctx->ctx.native_handle());
  auto client_side = [&]() -> dd::task<void> {
    std::vector<byte_t> to_send;
    for (;;) {
      io_error_code ec;
      bool done = client.handshake(to_send, /*is_client=*/true, ec);
      REQUIRE(!ec);
      if (done) {
        // в to_send последнее сообщение handshake (Finished), данные дописываются за ним
        REQUIRE(!to_send.empty());
        client.encrypt(data, to_send, ec);
        REQUIRE(!ec);
      }
      co_await net.write(client_sock, std::span<const byte_t>(to_send), ec);
      REQUIRE(!ec);
      to_send.clear();
      if (done)
        co_return;
      size_t n = co_await net.read_some(client_sock, client.input(), ec);
      REQUIRE(!ec);
      client.commit_readen_encrypted(n);
    }
  };
  background client_task;
  (void)client_task.run(client_side());

  io_error_code ec;
  co_await server.handshake(ec, /*is_client=*/false);
  REQUIRE(!ec);
  co_await client_task.join(ioctx);
  std::vector<byte_t> received(data.size());
  co_await read_awaiter(server, ec, received);
  REQUIRE(!ec);
  REQUIRE((received == data));
  co_await server.shutdown();
}

// данные любого размера доходят в обе стороны без искажений: от одного байта до многих TLS записей, с
// размерами на границах записи (2^14), любыми кусками записи и чтения
TRANSPORT_TEST("tls_connection transfers data to and from asio TLS socket") {
  const setup s = GENERATE_RANGE(all_setups_and_directions());
  tls_pair p(rawio, s);
  co_await p.handshake(s);

  side from = s.to_asio ? our_side(p) : peer_side(p);
  side to = s.to_asio ? peer_side(p) : our_side(p);
  SECTION("fixed sizes") {
    const size_t size = GENERATE(size_t(1), size_t(2), size_t(100), size_t(16383), size_t(16384),
                                 size_t(16385), size_t(2 * 16384), size_t(300'000));
    // целиком одной записью и одним чтением
    co_await transfer(p, from, to, size, size, size, /*seed=*/size);
    // и то же соединение дальше, мелкими кусками
    co_await transfer(p, from, to, size, 1000, 3000, /*seed=*/size + 1);
  }
  SECTION("random sizes and chunks") {
    const size_t seed = GENERATE_RANDOM(4);
    std::mt19937_64 rng(seed);
    // несколько сообщений подряд по одному соединению
    for (int i = 0; i < 4; ++i) {
      size_t size = 1 + rng() % 400'000;
      size_t max_write_chunk = 1 + rng() % 100'000;
      size_t max_read_chunk = 1 + rng() % 100'000;
      co_await transfer(p, from, to, size, max_write_chunk, max_read_chunk, rng());
    }
  }
  SECTION("many small writes, reads like HTTP/2 frames") {
    // заголовок фрейма (9 байт) и тело читаются отдельно, как это делает читатель HTTP/2
    const size_t seed = GENERATE_RANDOM(2);
    co_await transfer(p, from, to, 50'000, /*max_write_chunk=*/64, /*max_read_chunk=*/9, seed);
  }
}

// обе стороны одновременно пишут много данных и читают: чтение не мешает записи, которая упёрлась в
// заполненный сокет, и наоборот
TRANSPORT_TEST("tls_connection full duplex with asio TLS socket") {
  const setup s = GENERATE_RANGE(all_setups());
  tls_pair p(rawio, s);
  co_await p.handshake(s);
  SECTION("random") {
    const size_t seed = GENERATE_RANDOM(2);
    std::mt19937_64 rng(seed);
    size_t size = 200'000 + rng() % 400'000;
    background to_peer;
    (void)to_peer.run(transfer(p, our_side(p), peer_side(p), size, 50'000, 50'000, rng()));
    co_await transfer(p, peer_side(p), our_side(p), size, 50'000, 50'000, rng());
    co_await to_peer.join(p.ioctx);
  }
}

// запрос-ответ мелкими сообщениями: направление всё время меняется
TRANSPORT_TEST("tls_connection ping pong with asio TLS socket") {
  const setup s = GENERATE_RANGE(all_setups());
  tls_pair p(rawio, s);
  co_await p.handshake(s);
  SECTION("random") {
    const size_t seed = GENERATE_RANDOM(2);
    std::mt19937_64 rng(seed);
    for (int i = 0; i < 100; ++i) {
      size_t size = 1 + rng() % 300;
      co_await transfer(p, our_side(p), peer_side(p), size, size, size, rng());
      co_await transfer(p, peer_side(p), our_side(p), size, size, size, rng());
    }
  }
}

// TLS 1.3: любая сторона может сменить ключи посреди соединения (KeyUpdate) и потребовать того же от другой.
// Данные продолжают идти в обе стороны
TRANSPORT_TEST("tls_connection key update with asio TLS socket") {
  const setup s{.our_client = GENERATE(true, false), .peer_version = TLS1_3_VERSION};
  tls_pair p(rawio, s);
  co_await p.handshake(s);
  SSL* requester = nullptr;
  SECTION("requested by asio") {
    requester = p.peer->native_handle();
  }
  SECTION("requested by tls_connection") {
    requester = p.our_ssl();
  }
  for (size_t round = 0; round < 3; ++round) {
    REQUIRE(SSL_key_update(requester, SSL_KEY_UPDATE_REQUESTED));
    // KeyUpdate уходит со следующей записью запросившего, ответ - со следующей записью другой стороны
    co_await transfer(p, our_side(p), peer_side(p), 40'000, 10'000, 10'000, round);
    co_await transfer(p, peer_side(p), our_side(p), 40'000, 10'000, 10'000, round);
    co_await transfer(p, our_side(p), peer_side(p), 100, 100, 100, round);
    co_await transfer(p, peer_side(p), our_side(p), 100, 100, 100, round);
  }
}

// сокет asio пишет `data` и закрывает соединение: с close_notify или обрывает TCP без него
dd::task<void> peer_write_and_close(tls_pair& p, std::span<const byte_t> data, bool close_notify) {
  io_error_code ec;
  co_await peer_side(p).write(data, ec);
  REQUIRE(!ec);
  if (close_notify) {
    // завершится ошибкой: сокет asio ждёт ответного close_notify, а tls_connection его не отправляет
    co_await p.peer_close_notify(ec);
  } else {
    p.peer->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
  }
}

struct close_case {
  setup s;
  bool close_notify = true;
  // сколько сокет asio отправил до закрытия
  size_t sent = 0;
  // читатель просит ровно отправленное, а ошибку получает следующим чтением, или сразу просит больше
  bool read_more_than_sent = false;
};

std::vector<close_case> all_close_cases() {
  std::vector<close_case> result;
  for (const setup& s : all_setups())
    for (bool close_notify : {true, false})
      for (size_t sent : {size_t(1), size_t(20'000), size_t(200'000)})
        for (bool read_more_than_sent : {false, true})
          result.push_back({s, close_notify, sent, read_more_than_sent});
  return result;
}

// сокет asio закрывает соединение. Отправленное до этого читается, затем чтение возвращает ту же ошибку,
// что вернул бы сокет asio: eof после close_notify, stream_truncated после обрыва без него
TRANSPORT_TEST("tls_connection reads all data and error after asio TLS socket closes") {
  const close_case c = GENERATE_RANGE(all_close_cases());
  tls_pair p(rawio, c.s);
  co_await p.handshake(c.s);

  const io_error_code expected =
      c.close_notify ? io_error_code(boost::asio::error::eof) : io_error_code(ssl::error::stream_truncated);
  const std::vector<byte_t> data(c.sent, byte_t(7));
  background closing;
  (void)closing.run(peer_write_and_close(p, data, c.close_notify));

  io_error_code ec;
  if (c.read_more_than_sent) {
    std::vector<byte_t> received(data.size() + 1);
    co_await our_side(p).read(received, ec);
    REQUIRE(ec == expected);
  } else {
    std::vector<byte_t> received(data.size());
    co_await our_side(p).read(received, ec);
    REQUIRE(!ec);
    REQUIRE((received == data));
    byte_t more[1];
    co_await our_side(p).read(more, ec);
    REQUIRE(ec == expected);
  }
  co_await p.ours.shutdown();
  co_await closing.join(p.ioctx);
}

// shutdown закрывает соединение без close_notify: сокет asio получает stream_truncated. Чтение, которое в
// этот момент ждало данных, завершается с ошибкой, запись после shutdown невозможна
TRANSPORT_TEST("tls_connection shutdown seen by asio TLS socket") {
  const setup s = GENERATE_RANGE(all_setups());
  tls_pair p(rawio, s);
  co_await p.handshake(s);
  // до shutdown данные доходят
  co_await transfer(p, our_side(p), peer_side(p), 20'000, 20'000, 20'000, /*seed=*/1);

  background pending_read;
  io_error_code read_ec;
  byte_t never_sent[1];
  (void)pending_read.run(our_side(p).read(never_sent, read_ec));

  co_await p.ours.shutdown();
  co_await pending_read.join(p.ioctx);
  REQUIRE(read_ec);
  io_error_code ec;
  byte_t byte[1] = {};
  co_await our_side(p).write(byte, ec);
  REQUIRE(ec);

  ec.clear();
  co_await peer_side(p).read(byte, ec);
  REQUIRE(ec == ssl::error::stream_truncated);
}

// клиент библиотеки проверяет сертификат сервера и имя в нём, если задано host_for_name_verification
// при отказе клиент сообщает серверу причину алертом
TRANSPORT_TEST("tls client verifies certificate of asio TLS server") {
  any_io_context ioctx = make_asio_io_context(rawio);
  tcp::acceptor a(rawio, localhost());
  a.listen();
  // тестовый сертификат самоподписанный, в subjectAltName имя localhost и адреса 127.0.0.1 и ::1
  ssl_context_ptr server_ctx = test_server_ssl_ctx().p;
  asio_tls_stream server(rawio, server_ctx->ctx);

  tcp_connection_options opts;
  bool trusted = true;
  bool expect_success = false;
  SECTION("matching name") {
    opts.host_for_name_verification = "localhost";
    expect_success = true;
  }
  SECTION("matching ip address") {
    opts.host_for_name_verification = "127.0.0.1";
    expect_success = true;
  }
  SECTION("other name") {
    opts.host_for_name_verification = "example.com";
  }
  SECTION("other ip address") {
    opts.host_for_name_verification = "127.0.0.2";
  }
  SECTION("matching name, untrusted certificate") {
    opts.host_for_name_verification = "localhost";
    trusted = false;
  }
  SECTION("no verification") {
    trusted = false;
    expect_success = true;
  }
  std::filesystem::path cert = HTTP2_TLS_DIR "/test_server.crt";
  client_ssl_context_ptr client_ctx =
      make_ssl_context_for_client(trusted ? std::span(&cert, 1) : std::span<std::filesystem::path>());

  background accepting;
  io_error_code server_ec;
  auto accept_and_handshake = [&]() -> dd::task<void> {
    co_await net.accept(a, server.lowest_layer(), server_ec);
    REQUIRE(!server_ec);
    co_await net.handshake(server, ssl::stream_base::server, server_ec);
  };
  (void)accepting.run(accept_and_handshake());

  any_connection_t con = co_await ioctx.create_connection_client(
      {endpoint(std::string("localhost"), a.local_endpoint().port())}, deadline_after(5s), opts, client_ctx);
  io_error_code ec;
  co_await con.handshake(ec, /*is_client=*/true);
  REQUIRE_EQ(!ec, expect_success);
  co_await con.shutdown();
  co_await accepting.join(ioctx);
  REQUIRE_EQ(!server_ec, expect_success);
  if (!expect_success)
    REQUIRE(server_ec.category() == boost::asio::error::get_ssl_category());
}

REGISTER_TEST_LISTENER(moko3::gtest_listener);
MOKO3_MAIN;
