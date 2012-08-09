/* soup-websocket.c */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n-lib.h>

#include "soup.h"
#include "soup-filter-input-stream.h"
#include "soup-marshal.h"
#include "soup-misc-private.h"
#include "soup-websocket.h"
#include "soup-websocket-private.h"

#define DATA_HAS_N_BYTES(socket,n_bytes)                \
  (((socket)->priv->read_buf->len - (socket)->priv->read_offset) >= (n_bytes))

#define RESPONSE_BLOCK_SIZE (8192)
#define BLOCK_SIZE (0x0FFF)

G_DEFINE_TYPE (SoupWebsocket, soup_websocket, G_TYPE_OBJECT)

#define WEBSOCKET_PRIVATE(o) \
  (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_WEBSOCKET, SoupWebsocketPrivate))

enum {
  READY,
  MESSAGE,
  CLOSED,

  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


static void
soup_websocket_get_property (GObject    *object,
                             guint       property_id,
                             GValue     *value,
                             GParamSpec *pspec)
{
  switch (property_id)
    {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
soup_websocket_set_property (GObject      *object,
                             guint         property_id,
                             const GValue *value,
                             GParamSpec   *pspec)
{
  switch (property_id)
    {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
soup_websocket_dispose (GObject *object)
{
  SoupWebsocketPrivate *priv = ((SoupWebsocket *) object)->priv;

  if (priv->connection)
    {
      g_object_unref (priv->connection);
      priv->connection = NULL;
    }

  if (priv->istream)
    {
      g_object_unref (priv->istream);
      priv->istream = NULL;
    }

  if (priv->hs)
    {
      g_object_unref (priv->hs);
      priv->hs = NULL;
    }

  G_OBJECT_CLASS (soup_websocket_parent_class)->dispose (object);
}

static void
soup_websocket_finalize (GObject *object)
{
  SoupWebsocketPrivate *priv = ((SoupWebsocket *) object)->priv;

  if (priv->read_buf)
    g_byte_array_unref (priv->read_buf);

  if (priv->read_source)
    g_source_destroy (priv->read_source);

  if (priv->write_source)
    g_source_destroy (priv->write_source);

  G_OBJECT_CLASS (soup_websocket_parent_class)->finalize (object);
}

static void
soup_websocket_class_init (SoupWebsocketClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (SoupWebsocketPrivate));

  object_class->get_property = soup_websocket_get_property;
  object_class->set_property = soup_websocket_set_property;
  object_class->dispose = soup_websocket_dispose;
  object_class->finalize = soup_websocket_finalize;

  /**
   * SoupWebsocket::ready:
   * @socket: the websocket
   *
   * Emitted immediately after a successfull handshake.
   **/
  signals[READY] =
    g_signal_new ("ready",
                  G_OBJECT_CLASS_TYPE (object_class),
                  G_SIGNAL_RUN_FIRST,
                  0,
                  NULL, NULL,
                  _soup_marshal_NONE__NONE,
                  G_TYPE_NONE, 0);

  /**
   * SoupWebsocket::ready:
   * @socket: the websocket
   * @data: a pointer to the data received
   * @length: the length of the data received
   *
   * Emitted immediately after a message has been received.
   **/
  signals[MESSAGE] =
    g_signal_new ("message",
                  G_OBJECT_CLASS_TYPE (object_class),
                  G_SIGNAL_RUN_FIRST,
                  0,
                  NULL, NULL,
                  _soup_marshal_NONE__POINTER_UINT64,
                  G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_UINT64);

  /**
   * SoupWebsocket::closed:
   * @socket: the websocket
   *
   * Emitted after the connection has been closed (by error or
   * intentionnally).
   **/
  signals[CLOSED] =
    g_signal_new ("closed",
                  G_OBJECT_CLASS_TYPE (object_class),
                  G_SIGNAL_RUN_FIRST,
                  0,
                  NULL, NULL,
                  _soup_marshal_NONE__NONE,
                  G_TYPE_NONE, 0);
}

static void
soup_websocket_init (SoupWebsocket *self)
{
  self->priv = WEBSOCKET_PRIVATE (self);
}

SoupWebsocket *
soup_websocket_new (void)
{
  return g_object_new (SOUP_TYPE_WEBSOCKET, NULL);
}

/**/

static void
_soup_websocket_disconnect (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;

  g_message ("\tprocessing disconnect");

  if (priv->state == SOUP_WEBSOCKET_STATE_CLOSED)
    return;

  priv->state = SOUP_WEBSOCKET_STATE_CLOSED;

  if (priv->read_source)
    {
      g_source_destroy (priv->read_source);
      priv->read_source = NULL;
    }
  if (priv->write_source)
    {
      g_source_destroy (priv->write_source);
      priv->write_source = NULL;
    }

  g_clear_object (&priv->istream);
  priv->ostream = NULL;

  g_clear_object (&priv->connection);

  g_signal_emit (socket, signals[CLOSED], 0);
}

/**/

static gboolean
handle_control_frame (SoupWebsocket *socket)
{
  /* switch (data->opcode) */
  /*   { */
  /*   case OPCODE_CLOSE: */
  /*     { */
  /*       if (!data->close_frame_sent) */
  /*         { */
  /*           GError *error = NULL; */

  /*           if (!send_close_frame (data, 0, NULL, &error)) */
  /*             { */
  /*               /\* @TODO: handle error condition *\/ */
  /*               g_warning ("ERROR sending websocket close frame: %s\n", error->message); */
  /*               g_error_free (error); */

  /*               data->frame_state = EVD_WEBSOCKET_STATE_CLOSED; */
  /*               g_io_stream_close (G_IO_STREAM (data->conn), NULL, NULL); */
  /*             } */

  /*           data->close_frame_sent = TRUE; */
  /*         } */

  /*       evd_connection_flush_and_shutdown (EVD_CONNECTION (data->conn), NULL); */

  /*       data->state = EVD_WEBSOCKET_STATE_CLOSED; */
  /*       data->close_cb (EVD_HTTP_CONNECTION (data->conn), */
  /*                       TRUE, */
  /*                       data->user_data); */

  /*       break; */
  /*     } */

  /*   default: */
  /*     /\* @TODO: handle 'ping' and 'pong' control frames *\/ */
  /*     data->state = EVD_WEBSOCKET_STATE_CLOSED; */
  /*     g_io_stream_close (G_IO_STREAM (data->conn), NULL, NULL); */
  /*     g_warning ("Error, handling 'ping' and/or 'pong' control frames is not" */
  /*                " yet implemented in websocket version 08"); */
  /*     break; */
  /*   } */

  return TRUE;
}

/**/

static void
apply_masking (guint8 *frame, guint64 frame_len, guint8 masking_key[4])
{
  guint64 i;
  guint8 j;

  for (i = 0; i < frame_len; i++)
    {
      j = i % 4;
      frame[i] = frame[i] ^ masking_key[j];
    }
}

/**/

static gboolean
read_header (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;
  guint16 header = 0;

  if (!DATA_HAS_N_BYTES (socket, 2))
    return FALSE;

  header = ((guint8) priv->read_buf->data[priv->read_offset] << 8) +
    (guint8) priv->read_buf->data[priv->read_offset + 1];

  priv->read_offset += 2;

  /* fin flag */
  priv->fin = (guint16) (header & HEADER_MASK_FIN);
  /* opcode */
  priv->opcode = (guint8) ((header & HEADER_MASK_OPCODE) >> 8);
  /* masking */
  priv->masked = (guint16) (header & HEADER_MASK_MASKED);
  /* payload len */
  priv->payload_len = (guint16) (header & HEADER_MASK_PAYLOAD_LEN);

  /* @TODO: validate header values */

  if (priv->payload_len > 125)
    priv->frame_state = SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD_LEN;
  else if (priv->masked)
    priv->frame_state = SOUP_WEBSOCKET_FRAME_STATE_READING_MASKING_KEY;
  else
    priv->frame_state = SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD;

  return TRUE;
}

static gboolean
read_payload_len (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;

  if (priv->payload_len == 126)
    {
      guint16 len;

      if (!DATA_HAS_N_BYTES (socket, 2))
        return FALSE;

      memcpy (&len, priv->read_buf->data + priv->read_offset, 2);
      priv->read_offset += 2;

      priv->payload_len = (gsize) GUINT16_FROM_BE (len);
    }
  else
    {
      guint64 len;

      if (!DATA_HAS_N_BYTES (socket, 8))
        return FALSE;

      memcpy (&len, priv->read_buf->data + priv->read_offset, 8);
      priv->read_offset += 8;

      priv->payload_len = (gsize) GUINT64_FROM_BE (len);
    }

  /* @TODO: validated payload length against EVD_WEBSOCKET_MAX_PAYLOAD_SIZE */

  if (priv->masked)
    priv->frame_state = SOUP_WEBSOCKET_FRAME_STATE_READING_MASKING_KEY;
  else
    priv->frame_state = SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD;

  return TRUE;
}

static gboolean
read_payload (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;

  if (!DATA_HAS_N_BYTES (socket, priv->payload_len))
    return FALSE;

  priv->extension_data = priv->read_buf->data + priv->read_offset;

  priv->frame_len = priv->payload_len - priv->extension_len;
  priv->frame_data = priv->read_buf->data + priv->read_offset + priv->extension_len;

  if (priv->masked)
    apply_masking (priv->frame_data, priv->frame_len, priv->masking_key);

  if (priv->opcode >= OPCODE_CLOSE)
    {
      /* control frame */
      handle_control_frame (socket);
    }
  else
    {
      /* data frame */
      if (priv->fin)
        {
          g_signal_emit (socket, signals[MESSAGE], 0,
                         priv->frame_data, priv->frame_len);
        }
      else
        {
          /* TODO: fragmented frame, not supported yet */
          priv->state = SOUP_WEBSOCKET_STATE_CLOSED;
          /* g_io_stream_close (G_IO_STREAM (priv->conn), NULL, NULL); */
        }
    }

  /* reset state */
  priv->read_offset += priv->payload_len;
  priv->frame_state = SOUP_WEBSOCKET_FRAME_STATE_IDLE;

  g_message ("OLD read offset = %llu/%llu/%i",
             priv->read_offset, priv->write_offset, priv->read_buf->len);
  g_byte_array_remove_range (priv->read_buf, 0, priv->read_offset);
  priv->write_offset -= priv->read_offset;
  priv->read_offset = 0;
  g_message ("NEW read offset = %llu/%llu/%i",
             priv->read_offset, priv->write_offset, priv->read_buf->len);

  return TRUE;
}

static gboolean
read_masking_key (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;

  if (!DATA_HAS_N_BYTES (socket, 4))
    return FALSE;

  memcpy (&priv->masking_key, priv->read_buf->data + priv->read_offset, 4);

  priv->read_offset += 4;

  priv->state = SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD;
  if (priv->payload_len == 0)
    return read_payload (socket);

  return TRUE;
}

static gboolean
process_data (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;

  while ((priv->read_offset < priv->write_offset) &&
         (priv->state == SOUP_WEBSOCKET_STATE_OPEN))
    {
      switch (priv->frame_state)
        {
        case SOUP_WEBSOCKET_FRAME_STATE_IDLE:
          if (!read_header (socket))
            return TRUE;
          break;

        case SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD_LEN:
          if (!read_payload_len (socket))
            return TRUE;
          break;

        case SOUP_WEBSOCKET_FRAME_STATE_READING_MASKING_KEY:
          if (!read_masking_key (socket))
            return TRUE;
          break;

        case SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD:
          if (!read_payload (socket))
            return TRUE;
          break;

        case SOUP_WEBSOCKET_FRAME_STATE_READING_ERROR:
          priv->state = SOUP_WEBSOCKET_STATE_CLOSED;
          return FALSE;
        }
    }

  return TRUE;
}

static gboolean
read_data_stream (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;
  gsize nwrote;
  GError *myerror = NULL;

  g_message ("read steam data");

  if ((priv->read_buf->len - priv->write_offset) < BLOCK_SIZE)
    g_byte_array_set_size (priv->read_buf, priv->write_offset + BLOCK_SIZE);

  nwrote = g_pollable_input_stream_read_nonblocking (priv->istream,
                                                     priv->read_buf->data + priv->write_offset,
                                                     BLOCK_SIZE,
                                                     NULL,
                                                     &myerror);

  if (myerror)
    {
      g_warning ("read data error : %s", myerror->message);
      g_error_free (myerror);
      return FALSE;
    }

  if (nwrote < 1)
    {
      soup_connection_disconnect (priv->connection);
      return FALSE;
    }

  priv->write_offset += nwrote;

  return TRUE;
}

/**/

static gchar *
get_accept_key (const gchar *key)
{
  gchar *concat;
  GChecksum *checksum;
  guint8 *digest;
  gsize digest_len;
  gchar *accept;

  concat = g_strconcat (key, WEBSOCKET_MAGIC_UUID, NULL);

  checksum = g_checksum_new (G_CHECKSUM_SHA1);

  g_checksum_update (checksum, (guchar *) concat, -1);
  digest_len = g_checksum_type_get_length (G_CHECKSUM_SHA1);
  digest = g_slice_alloc (digest_len);
  g_checksum_get_digest (checksum, digest, &digest_len);

  accept = g_base64_encode (digest, digest_len);

  g_slice_free1 (digest_len, digest);
  g_checksum_free (checksum);
  g_free (concat);

  return accept;
}

static guint
parse_response_headers (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;
  SoupHTTPVersion version;
  const gchar *value;
  gchar *tmp;

  g_message ("received headers %s", priv->read_buf->data);

  g_free (priv->hs->reason_phrase);
  priv->hs->reason_phrase = NULL;
  if (!soup_headers_parse_response (priv->read_buf->data,
                                    priv->read_buf->len,
                                    priv->hs->response_headers,
                                    &version,
                                    &priv->hs->status_code,
                                    &priv->hs->reason_phrase))
    {
      g_byte_array_set_size (priv->read_buf, 0);
      return SOUP_STATUS_MALFORMED;
    }

  g_byte_array_set_size (priv->read_buf, 0);

  if (version < SOUP_HTTP_1_1)
    return SOUP_STATUS_MALFORMED;

  value = soup_message_headers_get_one (priv->hs->response_headers,
                                        "Upgrade");
  if (value == NULL || strcasecmp (value, "websocket"))
    return SOUP_STATUS_MALFORMED;

  value = soup_message_headers_get_one (priv->hs->response_headers,
                                        "Connection");
  if (value == NULL || strcasecmp (value, "Upgrade"))
    return SOUP_STATUS_MALFORMED;

  tmp = get_accept_key (soup_message_headers_get_one (priv->hs->request_headers,
                                                      "Sec-WebSocket-Key"));
  value = soup_message_headers_get_one (priv->hs->response_headers,
                                        "Sec-WebSocket-Accept");
  if (value == NULL || strcmp (value, tmp) != 0)
    {
      g_free (tmp);
      return SOUP_STATUS_MALFORMED;
    }
  g_free (tmp);

  value = soup_message_headers_get_one (priv->hs->response_headers,
                                        "Sec-WebSocket-Extensions");
  /* TODO: Stuff to do here as well... */


  return SOUP_STATUS_OK;
}

static gboolean
read_headers (SoupWebsocket *socket, GCancellable *cancellable, GError **error)
{
  SoupWebsocketPrivate *priv = socket->priv;
  SoupFilterInputStream *istream = SOUP_FILTER_INPUT_STREAM (priv->istream);
  gssize nread, old_len;
  gboolean got_lf;

  while (1) {
    old_len = priv->read_buf->len;
    g_byte_array_set_size (priv->read_buf, old_len + RESPONSE_BLOCK_SIZE);
    nread = soup_filter_input_stream_read_line (istream,
                                                priv->read_buf->data + old_len,
                                                RESPONSE_BLOCK_SIZE,
                                                FALSE/* TODO: io->blocking */,
                                                &got_lf,
                                                cancellable, error);
    priv->read_buf->len = old_len + MAX (nread, 0);
    if (nread == 0) {
      g_set_error_literal (error, G_IO_ERROR,
                           G_IO_ERROR_PARTIAL_INPUT,
                           _("Connection terminated unexpectedly"));
    }
    if (nread <= 0)
      return FALSE;

    if (got_lf) {
      if (nread == 1 && old_len >= 2 &&
          !strncmp ((char *)priv->read_buf->data +
                    priv->read_buf->len - 2,
                    "\n\n", 2))
        break;
      else if (nread == 2 && old_len >= 3 &&
               !strncmp ((char *)priv->read_buf->data +
                         priv->read_buf->len - 3,
                         "\n\r\n", 3))
        break;
    }
  }

  /* We need to "rewind" read_buf back one line. That SHOULD be two
   * characters (CR LF), but if the web server was stupid, it might
   * only be one.
   */
  if (priv->read_buf->len < 3 ||
      priv->read_buf->data[priv->read_buf->len - 2] == '\n')
    priv->read_buf->len--;
  else
    priv->read_buf->len -= 2;
  priv->read_buf->data[priv->read_buf->len] = '\0';

  return TRUE;
}

/**/

static gboolean
got_read_data_handshake (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;
  GError *myerror = NULL;

  switch (priv->hs_state)
    {
    case SOUP_WEBSOCKET_HANDSHAKE_STATE_NONE:
    case SOUP_WEBSOCKET_HANDSHAKE_STATE_CLIENT_HEADERS:
      break;

    case SOUP_WEBSOCKET_HANDSHAKE_STATE_SERVER_HEADERS:
      if (!read_headers (socket, NULL, &myerror))
        {
          if (myerror)
            {
              if (!g_error_matches (myerror, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
                {
                  g_error_free (myerror);
                  return G_SOURCE_REMOVE;
                }

              g_error_free (myerror);
            }

          return G_SOURCE_CONTINUE;
        }

      if (parse_response_headers (socket) != SOUP_STATUS_OK)
        {
          /* TODO: disconnect here */
          return G_SOURCE_REMOVE;
        }

      g_message ("PARSED HEADER!");

      priv->hs_state = SOUP_WEBSOCKET_HANDSHAKE_STATE_DONE;
      priv->state = SOUP_WEBSOCKET_STATE_OPEN;
      break;

    case SOUP_WEBSOCKET_HANDSHAKE_STATE_DONE:
      break;
    }

  return G_SOURCE_CONTINUE;
}

static gboolean
got_read_data (GIOChannel *source,
               SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;

  g_message ("read data!");

  switch (priv->state)
    {
    case SOUP_WEBSOCKET_STATE_NONE:
      break;

    case SOUP_WEBSOCKET_STATE_CONNECTING:
      return got_read_data_handshake (socket);

    case SOUP_WEBSOCKET_STATE_OPEN:
      while (read_data_stream (socket))
        {
          if (!process_data (socket))
            break;
        }
      if (priv->state == SOUP_WEBSOCKET_STATE_CLOSED)
        return G_SOURCE_REMOVE;
      break;

    case SOUP_WEBSOCKET_STATE_CLOSED:
      _soup_websocket_disconnect (socket);
      return G_SOURCE_REMOVE;
    }

  return G_SOURCE_CONTINUE;
}

/**/

static gboolean
got_write_data_handshake (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;
  GError *myerror = NULL;
  gsize nwrote;

  switch (priv->hs_state)
    {
    case SOUP_WEBSOCKET_HANDSHAKE_STATE_NONE:
    case SOUP_WEBSOCKET_HANDSHAKE_STATE_CLIENT_HEADERS:
      g_message ("write data handshake %p!", socket);

      nwrote =
        g_pollable_output_stream_write_nonblocking (priv->ostream,
                                                    &priv->hs_str->str[priv->hs_offset],
                                                    priv->hs_str->len - priv->hs_offset,
                                                    NULL, &myerror);

      if (myerror) {
        if (!g_error_matches (myerror, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
          {
            g_error_free (myerror);
            return G_SOURCE_REMOVE;
          }

        g_error_free (myerror);

        return G_SOURCE_CONTINUE;
      }

      if (nwrote >= 0)
        {
          priv->hs_offset += nwrote;
          if (priv->hs_offset >= priv->hs_str->len)
            {
              g_message ("wrote all headers");
              g_string_free (priv->hs_str, TRUE);
              priv->hs_str = NULL;
              priv->hs_state = SOUP_WEBSOCKET_HANDSHAKE_STATE_SERVER_HEADERS;

              g_source_destroy (priv->write_source);
              priv->write_source = NULL;
            }
        }
      break;

    case SOUP_WEBSOCKET_HANDSHAKE_STATE_SERVER_HEADERS:
      break;

    case SOUP_WEBSOCKET_HANDSHAKE_STATE_DONE:
      break;
    }

  return G_SOURCE_CONTINUE;
}

static gboolean
got_write_data (GIOChannel *source,
                SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;

  switch (priv->state)
    {
    case SOUP_WEBSOCKET_STATE_NONE:
    case SOUP_WEBSOCKET_STATE_CONNECTING:
      return got_write_data_handshake (socket);

    case SOUP_WEBSOCKET_STATE_OPEN:
      break;

    case SOUP_WEBSOCKET_STATE_CLOSED:
      _soup_websocket_disconnect (socket);
      return G_SOURCE_REMOVE;
    }

  return G_SOURCE_CONTINUE;
}

/**/

static void
got_socket_disconnected (SoupSocket *ssocket, SoupWebsocket *socket)
{
  g_message ("SOCKET DISCONNECTED!!!!");
}

static void
got_connection (SoupConnection *conn, guint status, SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv = socket->priv;
  SoupSocket *ssocket;
  GIOStream *iostream;
  GMainContext *async_context;

  g_message ("got connection s=%p status=%i!", socket, status);

  if (status != SOUP_STATUS_OK)
    {
      soup_connection_disconnect (priv->connection);
      return;
    }

  /* TODO: get the context from the soup connection */
  async_context = g_main_context_default ();

  ssocket = soup_connection_get_socket (priv->connection);
  g_signal_connect (ssocket, "disconnected",
                    G_CALLBACK (got_socket_disconnected), socket);

  iostream = soup_socket_get_iostream (ssocket);

  priv->istream = G_POLLABLE_INPUT_STREAM (soup_filter_input_stream_new (g_io_stream_get_input_stream (iostream)));
  priv->ostream = G_POLLABLE_OUTPUT_STREAM (g_io_stream_get_output_stream (iostream));

  priv->read_source = g_pollable_input_stream_create_source (priv->istream, NULL);
  g_source_set_callback (priv->read_source,
                         (GSourceFunc) got_read_data, socket, NULL);
  g_source_attach (priv->read_source, async_context);

  priv->write_source = g_pollable_output_stream_create_source (priv->ostream, NULL);
  g_source_set_callback (priv->write_source,
                         (GSourceFunc) got_write_data, socket, NULL);
  g_source_attach (priv->write_source, async_context);
}

static void
got_disconnected (SoupConnection *conn, SoupWebsocket *socket)
{
  g_message ("DISCONNECTED!!!!!!");

  _soup_websocket_disconnect (socket);
}

/**/

static void
build_handshake (SoupWebsocket *socket, SoupURI *uri)
{
  SoupWebsocketPrivate *priv = socket->priv;
  char *uri_host;
  char *uri_string;
  SoupMessageHeadersIter iter;
  const char *name, *value;
  gchar *base64;
  const guchar number[16] = { 0x42, 0x42, 0x42, 0x42,
                              0x42, 0x42, 0x42, 0x42,
                              0x42, 0x42, 0x42, 0x42,
                              0x42, 0x42, 0x42, 0x42 };
  SoupMessagePrivate *mpriv;

  priv->hs = soup_message_new_from_uri (SOUP_METHOD_GET, uri);;
  mpriv = SOUP_MESSAGE_GET_PRIVATE (priv->hs);
  priv->hs_str = g_string_new ("");
  priv->hs_offset = 0;

  soup_message_set_http_version (priv->hs, SOUP_HTTP_1_1);
  soup_message_headers_append (priv->hs->request_headers,
                               "Upgrade", "websocket");
  soup_message_headers_append (priv->hs->request_headers,
                               "Connection", "Upgrade");
  base64 = g_base64_encode (number, sizeof (number));
  soup_message_headers_append (priv->hs->request_headers,
                               "Sec-WebSocket-Key", base64);
  g_free (base64);
  soup_message_headers_append (priv->hs->request_headers,
                               "Sec-WebSocket-Version", "13");
  soup_message_headers_append (priv->hs->request_headers,
                               "Origin", "null");
  soup_message_headers_append (priv->hs->request_headers,
                               "Sec-WebSocket-Extensions",
                               "x-webkit-deflate-frame");


  if (strchr (uri->host, ':'))
    uri_host = g_strdup_printf ("[%s]", uri->host);
  else if (g_hostname_is_non_ascii (uri->host))
    uri_host = g_hostname_to_ascii (uri->host);
  else
    uri_host = uri->host;

  if (priv->hs->method == SOUP_METHOD_CONNECT) {
    /* CONNECT URI is hostname:port for tunnel destination */
    uri_string = g_strdup_printf ("%s:%d", uri_host, uri->port);
  } else {
    gboolean proxy = soup_connection_is_via_proxy (priv->connection);

    /* Proxy expects full URI to destination. Otherwise just the path.
     */
    uri_string = soup_uri_to_string (uri, !proxy);

    if (proxy && uri->fragment) {
      /* Strip fragment */
      char *fragment = strchr (uri_string, '#');
      if (fragment)
        *fragment = '\0';
    }
  }

  if (mpriv->http_version == SOUP_HTTP_1_0) {
    g_string_append_printf (priv->hs_str, "%s %s HTTP/1.0\r\n",
                            priv->hs->method, uri_string);
  } else {
    g_string_append_printf (priv->hs_str, "%s %s HTTP/1.1\r\n",
                            priv->hs->method, uri_string);
    if (!soup_message_headers_get_one (priv->hs->request_headers, "Host")) {
      if (soup_uri_uses_default_port (uri)) {
        g_string_append_printf (priv->hs_str, "Host: %s\r\n",
                                uri_host);
      } else {
        g_string_append_printf (priv->hs_str, "Host: %s:%d\r\n",
                                uri_host, uri->port);
      }
    }
  }
  g_free (uri_string);
  if (uri_host != uri->host)
    g_free (uri_host);

  /* *encoding = soup_message_headers_get_encoding (priv->hs->request_headers); */
  /* if ((*encoding == SOUP_ENCODING_CONTENT_LENGTH || */
  /*      *encoding == SOUP_ENCODING_NONE) && */
  /*     (priv->hs->request_body->length > 0 || */
  /*      soup_message_headers_get_one (priv->hs->request_headers, "Content-Type")) && */
  /*     !soup_message_headers_get_content_length (priv->hs->request_headers)) { */
  /*   *encoding = SOUP_ENCODING_CONTENT_LENGTH; */
  /*   soup_message_headers_set_content_length (priv->hs->request_headers, */
  /*                                            priv->hs->request_body->length); */
  /* } */

  soup_message_headers_iter_init (&iter, priv->hs->request_headers);
  while (soup_message_headers_iter_next (&iter, &name, &value))
    g_string_append_printf (priv->hs_str, "%s: %s\r\n", name, value);
  g_string_append (priv->hs_str, "\r\n");

  g_message ("built headers %s", priv->hs_str->str);
}

/**/

void
soup_websocket_connect_with_uri (SoupWebsocket *socket, SoupURI *uri)
{
  SoupWebsocketPrivate *priv;

  g_return_if_fail (SOUP_IS_WEBSOCKET (socket));

  priv = socket->priv;

  g_return_if_fail ((priv->state == SOUP_WEBSOCKET_STATE_NONE) ||
                    (priv->state == SOUP_WEBSOCKET_STATE_CLOSED));
  g_return_if_fail (SOUP_URI_IS_VALID (uri));

  priv->state = SOUP_WEBSOCKET_STATE_CONNECTING;
  priv->hs_state = SOUP_WEBSOCKET_HANDSHAKE_STATE_NONE;

  if (priv->connection)
    g_object_unref (priv->connection);

  priv->connection =
    g_object_new (SOUP_TYPE_CONNECTION,
                  SOUP_CONNECTION_REMOTE_URI, uri,
                  /* SOUP_CONNECTION_PROXY_RESOLVER, */
                  /* soup_session_get_feature (session, SOUP_TYPE_PROXY_URI_RESOLVER), */
                  /* SOUP_CONNECTION_SSL, uri_is_https (priv, soup_message_get_uri (item->msg)), */
                  /* SOUP_CONNECTION_SSL_CREDENTIALS, priv->tlsdb, */
                  /* SOUP_CONNECTION_SSL_STRICT, (priv->tlsdb != NULL) && priv->ssl_strict, */
                  /* SOUP_CONNECTION_ASYNC_CONTEXT, priv->async_context, */
                  /* SOUP_CONNECTION_USE_THREAD_CONTEXT, priv->use_thread_context, */
                  /* SOUP_CONNECTION_TIMEOUT, priv->io_timeout, */
                  /* SOUP_CONNECTION_IDLE_TIMEOUT, priv->idle_timeout, */
                  /* SOUP_CONNECTION_SSL_FALLBACK, host->ssl_fallback, */
                  NULL);

  build_handshake (socket, uri);

  if (priv->read_buf)
    g_byte_array_unref (priv->read_buf);
  priv->read_buf = g_byte_array_new ();

  g_signal_connect (priv->connection, "disconnected",
                    G_CALLBACK (got_disconnected),
                    socket);

  soup_connection_connect_async (priv->connection, NULL,
                                 (SoupConnectionCallback) got_connection,
                                 socket);
}

void
soup_websocket_connect (SoupWebsocket *socket, const gchar *uri_string)
{
  SoupURI *uri;

  g_return_if_fail (SOUP_IS_WEBSOCKET (socket));

  uri = soup_uri_new (uri_string);
  if (!uri)
    return;

  soup_websocket_connect_with_uri (socket, uri);
  soup_uri_free (uri);
}

void
soup_websocket_disconnect (SoupWebsocket *socket)
{
  SoupWebsocketPrivate *priv;

  g_return_if_fail (SOUP_IS_WEBSOCKET (socket));

  priv = socket->priv;

  g_return_if_fail ((priv->state == SOUP_WEBSOCKET_STATE_CONNECTING) ||
                    (priv->state == SOUP_WEBSOCKET_STATE_OPEN));

  soup_connection_disconnect (priv->connection);
}

SoupWebsocketState
soup_websocket_get_state (SoupWebsocket *socket)
{
  g_return_val_if_fail (SOUP_IS_WEBSOCKET (socket), SOUP_WEBSOCKET_STATE_NONE);

  return socket->priv->state;
}

static gboolean
soup_websocket_send_internal (SoupWebsocket *socket, SoupWebsocketMessage *msg)
{
  return TRUE;
}

gboolean
soup_websocket_send (SoupWebsocket *socket, gpointer data, guint length)
{
  SoupWebsocketMessage *msg;

  g_return_val_if_fail (SOUP_IS_WEBSOCKET (socket), FALSE);
  g_return_val_if_fail (data != NULL && length > 0, FALSE);

  msg = g_slice_new0 (SoupWebsocketMessage);

  msg->data = data;
  msg->length = length;

  return soup_websocket_send_internal (socket, msg);
}

/**/

static void
soup_websocket_queue_internal (SoupWebsocket *socket, SoupWebsocketMessage *msg)
{

}

void
soup_websocket_queue (SoupWebsocket *socket, gpointer data, guint length,
                      SoupWebsocketCallback callback, gpointer user_data)
{
  SoupWebsocketMessage *msg;

  g_return_if_fail (SOUP_IS_WEBSOCKET (socket));
  g_return_if_fail (data != NULL && length > 0);

  msg = g_slice_new0 (SoupWebsocketMessage);

  msg->data = data;
  msg->length = length;
  msg->callback = callback;
  msg->user_data = user_data;

  soup_websocket_queue_internal (socket, msg);
}
