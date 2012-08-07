#ifndef __SOUP_WEBSOCKET_PRIVATE_H__
#define __SOUP_WEBSOCKET_PRIVATE_H__

#include "soup-connection.h"
#include "soup-message.h"
#include "soup-websocket.h"

#define WEBSOCKET_MAGIC_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef enum
{
  SOUP_WEBSOCKET_HANDSHAKE_STATE_NONE,
  SOUP_WEBSOCKET_HANDSHAKE_STATE_CLIENT_HEADERS,
  SOUP_WEBSOCKET_HANDSHAKE_STATE_SERVER_HEADERS,
  SOUP_WEBSOCKET_HANDSHAKE_STATE_DONE
} SoupWebsocketHandshakeState;

typedef enum
{
  SOUP_WEBSOCKET_FRAME_STATE_IDLE,
  SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD_LEN,
  SOUP_WEBSOCKET_FRAME_STATE_READING_MASKING_KEY,
  SOUP_WEBSOCKET_FRAME_STATE_READING_PAYLOAD,
  SOUP_WEBSOCKET_FRAME_STATE_READING_ERROR
} SoupWebsocketFrameState;

typedef enum
{
  OPCODE_CONTINUATION     = 0x00,
  OPCODE_TEXT_FRAME       = 0x01,
  OPCODE_BINARY_FRAME     = 0x02,
  OPCODE_NON_CONTROL_RSV0 = 0x03,
  OPCODE_NON_CONTROL_RSV1 = 0x04,
  OPCODE_NON_CONTROL_RSV2 = 0x05,
  OPCODE_NON_CONTROL_RSV3 = 0x06,
  OPCODE_NON_CONTROL_RSV4 = 0x07,
  OPCODE_CLOSE            = 0x08,
  OPCODE_PING             = 0x09,
  OPCODE_PONG             = 0x0A,
  OPCODE_CONTROL_RSV0     = 0x0B,
  OPCODE_CONTROL_RSV1     = 0x0C,
  OPCODE_CONTROL_RSV2     = 0x0D,
  OPCODE_CONTROL_RSV3     = 0x0E,
  OPCODE_CONTROL_RSV4     = 0x0F
} SoupWebsocketOpcodes;

struct _SoupWebsocketPrivate
{
  SoupWebsocketState state;
  SoupWebsocketHandshakeState hs_state;

  SoupConnection *connection;

  GPollableInputStream *istream;
  GPollableOutputStream *ostream;

  GSource *read_source;
  GSource *write_source;

  SoupMessage *hs;
  GString *hs_str;
  guint hs_offset;

  /**/
  GByteArray *read_buf;
  guint64 read_offset;
  guint64 write_offset;

  guint8 *payload_data;
  guint64 payload_len;
  guint8 *extension_data;
  guint64 extension_len;
  guint8 *frame_data;
  guint64 frame_len;

  SoupWebsocketFrameState frame_state;
  gboolean fin;
  guint8 opcode;
  gboolean masked;
  guint8 masking_key[4];

  /* Queued messages to send */
  GList *messages;
};

typedef struct
{
  gpointer data;
  guint    length;

  guint write_offset;

  SoupWebsocketCallback callback;
  gpointer              user_data;
} SoupWebsocketMessage;

static const guint16 HEADER_MASK_FIN         = (1 << 15);
static const guint16 HEADER_MASK_OPCODE      = ((1 << 8) | (1 << 9) | (1 << 10) | (1 << 11));
static const guint16 HEADER_MASK_MASKED      = (1 << 7);
static const guint16 HEADER_MASK_PAYLOAD_LEN = (0x00FF & ~(1 << 7));

#endif /* __SOUP_WEBSOCKET_PRIVATE_H__ */
