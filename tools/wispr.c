/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <gweb/gweb.h>

#define DEFAULT_URL  "http://www.connman.net/online/status.html"

static GTimer *timer;

static GMainLoop *main_loop;

static void web_debug(const char *str, void *data)
{
	g_print("%s: %s\n", (const char *) data, str);
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

enum wispr_pages {
	WISPR_PAGE_NONE,
	WISPR_PAGE_REDIRECT,
	WISPR_PAGE_PROXY,
	WISPR_PAGE_AUTHENTICATION_REPLY,
	WISPR_PAGE_AUTHENTICATION_POLL_REPLY,
	WISPR_PAGE_LOGOFF_REPLY,
	WISPR_PAGE_ABORT_LOGIN_REPLY,
};

enum wispr_elements {
	WISPR_NONE,
	WISPR_ACCESS_PROCEDURE,
	WISPR_ACCESS_LOCATION,
	WISPR_LOCATION_NAME,
	WISPR_LOGIN_URL,
	WISPR_ABORT_LOGIN_URL,
	WISPR_MESSAGE_TYPE,
	WISPR_RESPONSE_CODE,
	WISPR_NEXT_URL,
	WISPR_DELAY,
	WISPR_REPLY_MESSAGE,
	WISPR_LOGIN_RESULTS_URL,
	WISPR_LOGOFF_URL,
};

static enum wispr_pages current_page = WISPR_NONE;
static enum wispr_elements current_element = WISPR_NONE;

static void start_element_handler(GMarkupParseContext *context,
					const gchar *element_name,
					const gchar **attribute_names,
					const gchar **attribute_values,
					gpointer user_data, GError **error)
{
	if (g_str_equal(element_name, "Redirect") == TRUE)
		current_page = WISPR_PAGE_REDIRECT;
	else if (g_str_equal(element_name, "Proxy") == TRUE)
		current_page = WISPR_PAGE_PROXY;
	else if (g_str_equal(element_name, "AuthenticationReply") == TRUE)
		current_page = WISPR_PAGE_AUTHENTICATION_REPLY;
	else if (g_str_equal(element_name, "AuthenticationPollReply") == TRUE)
		current_page = WISPR_PAGE_AUTHENTICATION_POLL_REPLY;
	else if (g_str_equal(element_name, "LogoffReply") == TRUE)
		current_page = WISPR_PAGE_LOGOFF_REPLY;
	else if (g_str_equal(element_name, "AbortLoginReply") == TRUE)
		current_page = WISPR_PAGE_ABORT_LOGIN_REPLY;
	else
		current_page = WISPR_PAGE_NONE;

	if (g_str_equal(element_name, "AccessProcedure") == TRUE)
		current_element = WISPR_ACCESS_PROCEDURE;
	else if (g_str_equal(element_name, "AccessLocation") == TRUE)
		current_element = WISPR_ACCESS_LOCATION;
	else if (g_str_equal(element_name, "LocationName") == TRUE)
		current_element = WISPR_LOCATION_NAME;
	else if (g_str_equal(element_name, "LoginURL") == TRUE)
		current_element = WISPR_LOGIN_URL;
	else if (g_str_equal(element_name, "AbortLoginURL") == TRUE)
		current_element = WISPR_ABORT_LOGIN_URL;
	else if (g_str_equal(element_name, "MessageType") == TRUE)
		current_element = WISPR_MESSAGE_TYPE;
	else if (g_str_equal(element_name, "ResponseCode") == TRUE)
		current_element = WISPR_RESPONSE_CODE;
	else if (g_str_equal(element_name, "NextURL") == TRUE)
		current_element = WISPR_NEXT_URL;
	else if (g_str_equal(element_name, "Delay") == TRUE)
		current_element = WISPR_DELAY;
	else if (g_str_equal(element_name, "ReplyMessage") == TRUE)
		current_element = WISPR_REPLY_MESSAGE;
	else if (g_str_equal(element_name, "LoginResultsURL") == TRUE)
		current_element = WISPR_LOGIN_RESULTS_URL;
	else if (g_str_equal(element_name, "LogoffURL") == TRUE)
		current_element = WISPR_LOGOFF_URL;
	else
		current_element = WISPR_NONE;
}

static void end_element_handler(GMarkupParseContext *context,
					const gchar *element_name,
					gpointer user_data, GError **error)
{
	current_page = WISPR_PAGE_NONE;

	current_element = WISPR_NONE;
}

static void text_handler(GMarkupParseContext *context,
					const gchar *text, gsize text_len,
					gpointer user_data, GError **error)
{
	int value;

	switch (current_page) {
	case WISPR_PAGE_NONE:
		break;
	case WISPR_PAGE_REDIRECT:
		printf("[ Redirect ]\n");
		break;
	case WISPR_PAGE_PROXY:
		printf("[ Proxy ]\n");
		break;
	case WISPR_PAGE_AUTHENTICATION_REPLY:
		printf("[ Authentication reply ]\n");
		break;
	case WISPR_PAGE_AUTHENTICATION_POLL_REPLY:
		printf("[ Authentication poll reply ]\n");
		break;
	case WISPR_PAGE_LOGOFF_REPLY:
		printf("[ Logoff reply ]\n");
		break;
	case WISPR_PAGE_ABORT_LOGIN_REPLY:
		printf("[ Abort login reply ]\n");
		break;
	}

	switch (current_element) {
	case WISPR_NONE:
		break;
	case WISPR_ACCESS_PROCEDURE:
		printf("Access procedure: %s\n", text);
		break;
	case WISPR_ACCESS_LOCATION:
		printf("Access location: %s\n", text);
		break;
	case WISPR_LOCATION_NAME:
		printf("Location name: %s\n", text);
		break;
	case WISPR_LOGIN_URL:
		printf("Login URL: %s\n", text);
		break;
	case WISPR_ABORT_LOGIN_URL:
		printf("Abort login URL: %s\n", text);
		break;
	case WISPR_MESSAGE_TYPE:
		value = atoi(text);
		printf("Message type: %d\n", value);
		switch (value) {
		case 100:
			printf("  Initial redirect message\n");
			break;
		case 110:
			printf("  Proxy notification\n");
			break;
		case 120:
			printf("  Authentication notification\n");
			break;
		case 130:
			printf("  Logoff notification\n");
			break;
		case 140:
			printf("  Response to Authentication Poll\n");
			break;
		case 150:
			printf("  Response to Abort Login\n");
			break;
		}
		break;
	case WISPR_RESPONSE_CODE:
		value = atoi(text);
		printf("Response code: %d\n", value);
		switch (value) {
		case 0:
			printf("  No error\n");
			break;
		case 50:
			printf("  Login succeeded (Access ACCEPT)\n");
			break;
		case 100:
			printf("  Login failed (Access REJECT)\n");
			break;
		case 102:
			printf("  RADIUS server error/timeout\n");
			break;
		case 105:
			printf("  RADIUS server not enabled\n");
			break;
		case 150:
			printf("  Logoff succeeded\n");
			break;
		case 151:
			printf("  Login aborted\n");
			break;
		case 200:
			printf("  Proxy detection/repeat operation\n");
			break;
		case 201:
			printf("  Authentication pending\n");
			break;
		case 255:
			printf("  Access gateway internal error\n");
			break;
		}
		break;
	case WISPR_NEXT_URL:
		printf("Next URL: %s\n", text);
		break;
	case WISPR_DELAY:
		value = atoi(text);
		printf("Delay: %d seconds\n", value);
		break;
	case WISPR_REPLY_MESSAGE:
		printf("Reply message: %s\n", text);
		break;
	case WISPR_LOGIN_RESULTS_URL:
		printf("Login results URL: %s\n", text);
		break;
	case WISPR_LOGOFF_URL:
		printf("Logoff URL: %s\n", text);
		break;
	}
}

static void error_handler(GMarkupParseContext *context,
					GError *error, gpointer user_data)
{
	printf("%s\n", error->message);
}

static const GMarkupParser wispr_parser = {
	start_element_handler,
	end_element_handler,
	text_handler,
	NULL,
	error_handler,
};

static void parser_callback(const char *str, gpointer user_data)
{
	GMarkupParseContext *context;
	gboolean result;

	//printf("%s\n", str);

	context = g_markup_parse_context_new(&wispr_parser,
				G_MARKUP_TREAT_CDATA_AS_TEXT, NULL, NULL);

	result = g_markup_parse_context_parse(context, str, strlen(str), NULL);

	result = g_markup_parse_context_end_parse(context, NULL);

	g_markup_parse_context_free(context);
}

static guint request_id;
static GWebParser *request_parser;

static gboolean web_result(GWebResult *result, gpointer user_data)
{
	const guint8 *chunk;
	gsize length;
	guint16 status;
	gdouble elapsed;

	status = g_web_result_get_status(result);
	if (status == 200)
		goto done;

	g_web_result_get_chunk(result, &chunk, &length);

	if (length > 0) {
		//printf("%s\n", (char *) chunk);
		g_web_parser_feed_data(request_parser, chunk, length);
		return TRUE;
	}

	g_web_parser_end_data(request_parser);

done:
	g_print("status: %03u\n", status);

	elapsed = g_timer_elapsed(timer, NULL);

	g_print("elapse: %f seconds\n", elapsed);

	g_main_loop_quit(main_loop);

	return FALSE;
}

static gboolean option_debug = FALSE;
static gchar *option_nameserver = NULL;
static gchar *option_url = NULL;

static GOptionEntry options[] = {
	{ "debug", 'd', 0, G_OPTION_ARG_NONE, &option_debug,
					"Enable debug output" },
	{ "nameserver", 'n', 0, G_OPTION_ARG_STRING, &option_nameserver,
					"Specify nameserver", "ADDRESS" },
	{ "url", 'u', 0, G_OPTION_ARG_STRING, &option_url,
					"Specify arbitrary request", "URL" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	struct sigaction sa;
	GWeb *web;
	int index = 0;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &error) == FALSE) {
		if (error != NULL) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		return 1;
	}

	g_option_context_free(context);

	web = g_web_new(index);
	if (web == NULL) {
		fprintf(stderr, "Failed to create web service\n");
		return 1;
	}

	if (option_debug == TRUE)
		g_web_set_debug(web, web_debug, "WEB");

	main_loop = g_main_loop_new(NULL, FALSE);

	if (option_nameserver != NULL) {
		g_web_add_nameserver(web, option_nameserver);
		g_free(option_nameserver);
	}

	g_web_set_accept(web, NULL);
	g_web_set_user_agent(web, "SmartClient/%s wispr", VERSION);
	g_web_set_close_connection(web, TRUE);

	if (option_url == NULL)
		option_url = g_strdup(DEFAULT_URL);

	timer = g_timer_new();

	request_parser = g_web_parser_new("<WISPAccessGatewayParam",
						"WISPAccessGatewayParam>",
						parser_callback, NULL);

	g_web_parser_ref(request_parser);
	g_web_parser_unref(request_parser);

	request_id = g_web_request_get(web, option_url, web_result, NULL);

	g_free(option_url);

	if (request_id == 0) {
		fprintf(stderr, "Failed to start request\n");
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	g_timer_destroy(timer);

	g_web_unref(web);

	g_main_loop_unref(main_loop);

	return 0;
}
