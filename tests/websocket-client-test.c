/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Intel Corporation
 */

#include "test-utils.h"

static gchar *websocket_uri = NULL;

static GOptionEntry websocket_entry[] = {
  { "uri", 'u', G_OPTION_FLAG_IN_MAIN,
    G_OPTION_ARG_STRING, &websocket_uri,
    "URI of the server to connect to", NULL },
  { NULL }
};

static void
on_ready (SoupWebsocket *socket, gpointer user_data)
{
  g_message ("Socket ready!");
}

static void
on_message (SoupWebsocket *socket,
            gpointer data, guint64 size,
            gpointer user_data)
{
  g_message ("Socket message size=%lu!", size);
  g_message ("-> %s", (gchar *) data);
}

int
main (int argc, char **argv)
{
  GMainLoop *loop;
  SoupWebsocket *socket;

  test_init (argc, argv, websocket_entry);

  if (!websocket_uri)
    {
      test_cleanup ();
      return 1;
    }

  loop = g_main_loop_new (NULL, FALSE);

  socket = soup_websocket_new ();
  g_message ("s=%p", socket);

  g_signal_connect (socket, "ready", G_CALLBACK (on_ready), NULL);
  g_signal_connect (socket, "message", G_CALLBACK (on_message), NULL);

  soup_websocket_connect (socket, websocket_uri);

  g_main_loop_run (loop);

  test_cleanup ();

  return 0;
}
