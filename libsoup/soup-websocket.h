/* soup-websocket.h */

#ifndef __SOUP_WEBSOCKET_H__
#define __SOUP_WEBSOCKET_H__

#include <libsoup/soup-uri.h>

G_BEGIN_DECLS

#define SOUP_TYPE_WEBSOCKET soup_websocket_get_type()

#define SOUP_WEBSOCKET(obj) \
  (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
  SOUP_TYPE_WEBSOCKET, SoupWebsocket))

#define SOUP_WEBSOCKET_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_CAST ((klass), \
  SOUP_TYPE_WEBSOCKET, SoupWebsocketClass))

#define SOUP_IS_WEBSOCKET(obj) \
  (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
  SOUP_TYPE_WEBSOCKET))

#define SOUP_IS_WEBSOCKET_CLASS(klass) \
  (G_TYPE_CHECK_CLASS_TYPE ((klass), \
  SOUP_TYPE_WEBSOCKET))

#define SOUP_WEBSOCKET_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), \
  SOUP_TYPE_WEBSOCKET, SoupWebsocketClass))

typedef enum
{
  SOUP_WEBSOCKET_STATE_NONE,
  SOUP_WEBSOCKET_STATE_CONNECTING,
  SOUP_WEBSOCKET_STATE_OPEN,
  SOUP_WEBSOCKET_STATE_CLOSED
} SoupWebsocketState;

typedef struct _SoupWebsocket SoupWebsocket;
typedef struct _SoupWebsocketClass SoupWebsocketClass;
typedef struct _SoupWebsocketPrivate SoupWebsocketPrivate;

typedef void (*SoupWebsocketCallback) (SoupSession *session,
                                       gpointer     data,
                                       guint        length,
                                       gpointer     user_data);

struct _SoupWebsocket
{
  GObject parent;

  SoupWebsocketPrivate *priv;
};

struct _SoupWebsocketClass
{
  GObjectClass parent_class;
};

GType soup_websocket_get_type (void) G_GNUC_CONST;

SoupWebsocket *soup_websocket_new (void);

void soup_websocket_connect_with_uri (SoupWebsocket *socket, SoupURI *uri);
void soup_websocket_connect (SoupWebsocket *socket, const gchar *uri);

void soup_websocket_disconnect (SoupWebsocket *socket);

SoupWebsocketState soup_websocket_get_state (SoupWebsocket *socket);

gboolean soup_websocket_send (SoupWebsocket *socket, gpointer data, guint length);

void soup_websocket_queue (SoupWebsocket *socket, gpointer data, guint length,
                           SoupWebsocketCallback callback, gpointer user_data);

G_END_DECLS

#endif /* __SOUP_WEBSOCKET_H__ */
