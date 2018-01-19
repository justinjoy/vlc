/*****************************************************************************
 * srt.c: SRT (Secure Reliable Transport) input module
 *****************************************************************************
 * Copyright (C) 2017, Collabora Ltd.
 *
 * Authors: Justin Kim <justin.kim@collabora.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <errno.h>
#ifdef HAVE_POLL
# include <poll.h>
#endif

#include <vlc_common.h>
#include <vlc_interrupt.h>
#include <vlc_fs.h>
#include <vlc_plugin.h>
#include <vlc_access.h>

#include <vlc_network.h>
#include <vlc_url.h>

#include <srt/srt.h>

/* libsrt defines default packet size as 1316 internally
 * so srt module takes same value. */
#define SRT_DEFAULT_CHUNK_SIZE 1316
/* The default latency is 125
 * which uses srt library internally */
#define SRT_DEFAULT_LATENCY 125
/* Crypto key length in bytes. */
#define SRT_KEY_LENGTH_TEXT N_("Crypto key length in bytes")
#define SRT_DEFAULT_KEY_LENGTH 16
static const int srt_key_lengths[] = {
    16, 24, 32,
};

static const char *const srt_key_length_names[] = {
    N_("16 bytes"), N_("24 bytes"), N_("32 bytes"),
};

struct stream_sys_t
{
    SRTSOCKET   sock;
    vlc_thread_t thread;
    bool        b_woken;
    block_fifo_t *fifo;

};

static void *Thread(void *p_data)
{
    stream_t *p_stream = p_data;
    stream_sys_t *p_sys = p_stream->p_sys;

    size_t i_chunk_size = var_InheritInteger( p_stream, "chunk-size" );

    for(;;)
    {

        struct pollfd ufd;
        ufd.fd = srt_socket_get_fd( p_sys->sock, SRTF_RECEIVER );
        ufd.events = POLLIN;

        if (ufd.fd < 1)
        {
            msg_Err( p_stream, "Invalid SRT socket(reason: %s)", srt_getlasterror_str() );
            break;
        }

        if (poll( &ufd, 1, 10 ) == -1 )
        {
            break;
        }

        block_t *pkt = block_Alloc( i_chunk_size );

        if ( unlikely( pkt == NULL ) )
        {
            break;
        }

        int stat = srt_recvmsg( p_sys->sock, (char *)pkt->p_buffer, i_chunk_size );

        if ( stat == SRT_ERROR )
        {
            msg_Err( p_stream, "failed to recevie SRT packet (reason: %s)", srt_getlasterror_str() );
            block_Release( pkt );
            break;
        }

        pkt->i_buffer = stat;
        block_FifoPut( p_sys->fifo, pkt );
    }

    vlc_fifo_Lock( p_sys->fifo );
    p_sys->b_woken = true;
    vlc_fifo_Signal( p_sys->fifo );
    vlc_fifo_Unlock( p_sys->fifo );

    return NULL;
}

static int Control(stream_t *p_stream, int i_query, va_list args)
{
    int i_ret = VLC_SUCCESS;

    switch( i_query )
    {
        case STREAM_CAN_SEEK:
        case STREAM_CAN_FASTSEEK:
        case STREAM_CAN_PAUSE:
        case STREAM_CAN_CONTROL_PACE:
            *va_arg( args, bool * ) = false;
            break;
        case STREAM_GET_PTS_DELAY:
            *va_arg( args, int64_t * ) = INT64_C(1000)
                   * var_InheritInteger(p_stream, "network-caching");
            break;
        default:
            i_ret = VLC_EGENERIC;
            break;
    }

    return i_ret;
}

static block_t *BlockSRT(stream_t *p_stream, bool *restrict eof)
{
    stream_sys_t *p_sys = p_stream->p_sys;
    block_t *pkt;

    vlc_fifo_Lock( p_sys->fifo );

    while( vlc_fifo_IsEmpty( p_sys->fifo ) ) {
        if( p_sys->b_woken )
            break;
        vlc_fifo_Wait( p_sys->fifo );
    }

    if ( ( pkt = vlc_fifo_DequeueUnlocked( p_sys->fifo ) ) == NULL)
        *eof = true;
    p_sys->b_woken = false;
    vlc_fifo_Unlock( p_sys->fifo );

    return pkt;
}

static int Open(vlc_object_t *p_this)
{
    stream_t     *p_stream = (stream_t*)p_this;
    stream_sys_t *p_sys = NULL;
    vlc_url_t     parsed_url = { 0 };
    struct addrinfo hints = {
        .ai_socktype = SOCK_DGRAM,
    }, *res = NULL;
    int stat;

    char         *psz_passphrase = NULL;
    int           i_latency;

    p_sys = vlc_obj_calloc( p_this, 1, sizeof( *p_sys ) );
    if( unlikely( p_sys == NULL ) )
        return VLC_ENOMEM;

    if ( vlc_UrlParse( &parsed_url, p_stream->psz_url ) == -1 )
    {
        msg_Err( p_stream, "Failed to parse a given URL (%s)", p_stream->psz_url );
        goto failed;
    }

    p_stream->p_sys = p_sys;
    p_stream->pf_block = BlockSRT;
    p_stream->pf_control = Control;

    psz_passphrase = var_InheritString( p_stream, "passphrase" );

    stat = vlc_getaddrinfo( parsed_url.psz_host, parsed_url.i_port, &hints, &res );
    if ( stat )
    {
        msg_Err( p_stream, "Cannot resolve [%s]:%d (reason: %s)",
                 parsed_url.psz_host,
                 parsed_url.i_port,
                 gai_strerror( stat ) );

        goto failed;
    }

    p_sys->sock = srt_socket( res->ai_family, SOCK_DGRAM, 0 );
    if ( p_sys->sock == SRT_ERROR )
    {
        msg_Err( p_stream, "Failed to open socket." );
        goto failed;
    }

    /* Make SRT non-blocking */
    srt_setsockopt( p_sys->sock, 0, SRTO_SNDSYN, &(bool) { false }, sizeof( bool ) );

    /* Make sure TSBPD mode is enable (SRT mode) */
    srt_setsockopt( p_sys->sock, 0, SRTO_TSBPDMODE, &(int) { 1 }, sizeof( int ) );

    /* Set latency */
    i_latency = var_InheritInteger( p_stream, "latency" );
    srt_setsockopt( p_sys->sock, 0, SRTO_TSBPDDELAY, &i_latency, sizeof( int ) );

    if ( psz_passphrase != NULL && psz_passphrase[0] != '\0')
    {
        int i_key_length = var_InheritInteger( p_stream, "key-length" );

        srt_setsockopt( p_sys->sock, 0, SRTO_PASSPHRASE,
            psz_passphrase, strlen( psz_passphrase ) );
        srt_setsockopt( p_sys->sock, 0, SRTO_PBKEYLEN,
            &i_key_length, sizeof( int ) );
    }

    stat = srt_connect( p_sys->sock, res->ai_addr, sizeof (struct sockaddr) );

    if ( stat == SRT_ERROR )
    {
        msg_Err( p_stream, "Failed to connect to server." );
        goto failed;
    }

    p_sys->fifo = block_FifoNew();
    if ( !p_sys->fifo )
    {
        msg_Err( p_stream, "Failed to allocate block fifo." );
        goto failed;
    }

    if ( vlc_clone( &p_sys->thread, Thread, p_stream, VLC_THREAD_PRIORITY_INPUT ) )
    {
        msg_Err( p_stream, "Failed to create thread." );
        goto failed;
    }

    vlc_UrlClean( &parsed_url );
    freeaddrinfo( res );
    free (psz_passphrase);

    return VLC_SUCCESS;

failed:
    if ( p_sys->fifo )
        block_FifoRelease( p_sys->fifo );

    if ( parsed_url.psz_host != NULL
      && parsed_url.psz_buffer != NULL)
    {
        vlc_UrlClean( &parsed_url );
    }

    if ( res != NULL )
    {
        freeaddrinfo( res );
    }

    srt_close( p_sys->sock );

    free (psz_passphrase);

    return VLC_EGENERIC;
}

static void Close(vlc_object_t *p_this)
{
    stream_t     *p_stream = (stream_t*)p_this;
    stream_sys_t *p_sys = p_stream->p_sys;

    vlc_cancel( p_sys->thread );
    vlc_join( p_sys->thread, NULL );

    block_FifoRelease( p_sys->fifo );

    msg_Dbg( p_stream, "closing server" );
    srt_close( p_sys->sock );
}

/* Module descriptor */
vlc_module_begin ()
    set_shortname( N_("SRT") )
    set_description( N_("SRT input") )
    set_category( CAT_INPUT )
    set_subcategory( SUBCAT_INPUT_ACCESS )

    add_integer( "chunk-size", SRT_DEFAULT_CHUNK_SIZE,
            N_("SRT chunk size (bytes)"), NULL, true )
    add_integer( "latency", SRT_DEFAULT_LATENCY, N_("SRT latency (ms)"), NULL, true )
    add_password( "passphrase", "", N_("Password for stream encryption"), NULL, false )
    add_integer( "key-length", SRT_DEFAULT_KEY_LENGTH,
            SRT_KEY_LENGTH_TEXT, SRT_KEY_LENGTH_TEXT, false )
        change_integer_list( srt_key_lengths, srt_key_length_names )

    set_capability( "access", 0 )
    add_shortcut( "srt" )

    set_callbacks( Open, Close )
vlc_module_end ()
