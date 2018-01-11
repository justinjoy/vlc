/*****************************************************************************
 * srt.c: SRT (Secure Reliable Transport) output module
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
#include <fcntl.h>

#include <vlc_common.h>
#include <vlc_interrupt.h>
#include <vlc_fs.h>
#include <vlc_plugin.h>
#include <vlc_sout.h>
#include <vlc_block.h>
#include <vlc_network.h>

#include <srt/srt.h>

/* libsrt defines default packet size as 1316 internally
 * so srt module takes same value. */
#define SRT_DEFAULT_CHUNK_SIZE 1316
/* libsrt tutorial uses 9000 as a default binding port */
#define SRT_DEFAULT_PORT 9000
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

struct sout_access_out_sys_t
{
    SRTSOCKET     sock;
    vlc_thread_t  thread;
    block_fifo_t *fifo;
};

static void *Thread(void *p_data)
{
    sout_access_out_t *p_access = p_data;
    sout_access_out_sys_t *p_sys = p_access->p_sys;
    size_t i_chunk_size = var_InheritInteger( p_access, "chunk-size" );
    for(;;)
    {
        block_t *pkt = block_FifoGet( p_sys->fifo );

        while( pkt->i_buffer )
        {
            size_t i_write = __MIN( pkt->i_buffer, i_chunk_size );

            block_cleanup_push( pkt );
            if ( srt_sendmsg2( p_sys->sock, (char *)pkt->p_buffer, i_write, 0 ) == SRT_ERROR )
                msg_Warn( p_access, "send error: %s", srt_getlasterror_str() );
            vlc_cleanup_pop();

            pkt->p_buffer += i_write;
            pkt->i_buffer -= i_write;
        }

        block_Release( pkt );
    }

    return NULL;
}

static ssize_t Write( sout_access_out_t *p_access, block_t *p_buffer )
{
    sout_access_out_sys_t *p_sys = p_access->p_sys;
    int i_len = 0;

    while( p_buffer )
    {
        block_t *p_next = p_buffer->p_next;
        i_len += p_buffer->i_buffer;

        block_FifoPut( p_sys->fifo, p_buffer );

        p_buffer = p_next;
    }

    return i_len;
}

static int Control( sout_access_out_t *p_access, int i_query, va_list args )
{
    VLC_UNUSED (p_access);

    int i_ret = VLC_SUCCESS;

    switch( i_query )
    {
        case ACCESS_OUT_CONTROLS_PACE:
            *va_arg( args, bool * ) = false;
            break;

        default:
            i_ret = VLC_EGENERIC;
            break;
    }

    return i_ret;
}

static int Open( vlc_object_t *p_this )
{
    sout_access_out_t       *p_access = (sout_access_out_t*)p_this;
    sout_access_out_sys_t   *p_sys = NULL;

    char                    *psz_dst_addr = NULL;
    int                      i_dst_port;
    int                      stat;
    char                    *psz_passphrase = NULL;
    int                      i_latency;

    struct addrinfo hints = {
        .ai_socktype = SOCK_DGRAM,
    }, *res = NULL;

    if (var_Create ( p_access, "dst-port", VLC_VAR_INTEGER )
     || var_Create ( p_access, "src-port", VLC_VAR_INTEGER )
     || var_Create ( p_access, "dst-addr", VLC_VAR_STRING )
     || var_Create ( p_access, "src-addr", VLC_VAR_STRING ) )
    {
         msg_Err( p_access, "Valid network information is required." );
        return VLC_ENOMEM;
    }

    if( !( p_sys = calloc (1, sizeof( *p_sys ) ) ) )
        return VLC_ENOMEM;

    p_access->p_sys = p_sys;

    psz_passphrase = var_InheritString( p_access, "passphrase" );

    i_dst_port = SRT_DEFAULT_PORT;
    char *psz_parser = psz_dst_addr = strdup( p_access->psz_path );
    if( !psz_dst_addr )
    {
        free( p_sys );
        return VLC_ENOMEM;
    }

    if (psz_parser[0] == '[')
        psz_parser = strchr (psz_parser, ']');

    psz_parser = strchr (psz_parser ? psz_parser : psz_dst_addr, ':');
    if (psz_parser != NULL)
    {
        *psz_parser++ = '\0';
        i_dst_port = atoi (psz_parser);
    }

    msg_Dbg( p_access, "Setting SRT socket (dest addresss: %s, port: %d).",
             psz_dst_addr, i_dst_port );

    stat = vlc_getaddrinfo( psz_dst_addr, i_dst_port, &hints, &res );
    if ( stat )
    {
        msg_Err( p_access, "Cannot resolve [%s]:%d (reason: %s)",
                 psz_dst_addr,
                 i_dst_port,
                 gai_strerror( stat ) );

        goto failed;
    }

    p_sys->sock = srt_socket( res->ai_family, SOCK_DGRAM, 0 );
    if ( p_sys->sock == SRT_ERROR )
    {
        msg_Err( p_access, "Failed to open socket." );
        goto failed;
    }

    /* Make SRT blocking */
    srt_setsockopt( p_sys->sock, 0, SRTO_SNDSYN, &(bool) { true }, sizeof( bool ) );

    /* Make sure TSBPD mode is enable (SRT mode) */
    srt_setsockopt( p_sys->sock, 0, SRTO_TSBPDMODE, &(int) { 1 }, sizeof( int ) );

    /* This is an access_out so it is always a sender */
    srt_setsockopt( p_sys->sock, 0, SRTO_SENDER, &(int) { 1 }, sizeof( int ) );

    /* Set latency */
    i_latency = var_InheritInteger( p_access, "latency" );
    srt_setsockopt( p_sys->sock, 0, SRTO_TSBPDDELAY, &i_latency, sizeof( int ) );

    if ( psz_passphrase != NULL && psz_passphrase[0] != '\0')
    {
        int i_key_length = var_InheritInteger( p_access, "key-length" );
        srt_setsockopt( p_sys->sock, 0, SRTO_PASSPHRASE,
            psz_passphrase, strlen( psz_passphrase ) );
        srt_setsockopt( p_sys->sock, 0, SRTO_PBKEYLEN,
            &i_key_length, sizeof( int ) );
    }

    srt_setsockopt( p_sys->sock, 0, SRTO_SENDER, &(int) { 1 }, sizeof(int) );

    stat = srt_connect( p_sys->sock, res->ai_addr, sizeof (struct sockaddr));
    if ( stat == SRT_ERROR )
    {
        msg_Err( p_access, "Failed to connect to server (reason: %s)",
                 srt_getlasterror_str() );
        goto failed;
    }

    p_access->pf_write = Write;
    p_access->pf_control = Control;

    p_sys->fifo = block_FifoNew();
    if ( !p_sys->fifo )
    {
        msg_Err( p_access, "Failed to allocate block fifo." );
        goto failed;
    }

    if ( vlc_clone( &p_sys->thread, Thread, p_access, VLC_THREAD_PRIORITY_HIGHEST ) )
    {
        msg_Err( p_access, "Failed to create thread." );
        goto failed;
    }

    free( psz_passphrase );
    free( psz_dst_addr );
    freeaddrinfo( res );

    return VLC_SUCCESS;

failed:
    if ( p_sys->fifo )
        block_FifoRelease( p_sys->fifo );

    free( psz_passphrase );

    if ( psz_dst_addr != NULL)
        free( psz_dst_addr );

    if ( res != NULL )
        freeaddrinfo( res );

    if ( p_sys != NULL )
    {
        if ( p_sys->sock != -1 ) srt_close( p_sys->sock );

        free( p_sys );
    }

    return VLC_EGENERIC;
}

static void Close( vlc_object_t * p_this )
{
    sout_access_out_t     *p_access = (sout_access_out_t*)p_this;
    sout_access_out_sys_t *p_sys = p_access->p_sys;

    vlc_cancel( p_sys->thread );
    vlc_join( p_sys->thread, NULL );

    block_FifoRelease( p_sys->fifo );

    srt_close( p_sys->sock );

    free( p_sys );
}

/* Module descriptor */
vlc_module_begin()
    set_shortname( N_("SRT") )
    set_description( N_("SRT stream output") )
    set_category( CAT_SOUT )
    set_subcategory( SUBCAT_SOUT_ACO )

    add_integer( "chunk-size", SRT_DEFAULT_CHUNK_SIZE,
            N_("SRT chunk size (bytes)"), NULL, true )
    add_integer( "latency", SRT_DEFAULT_LATENCY, N_("SRT latency (ms)"), NULL, true )
    add_password( "passphrase", "", N_("Password for stream encryption"), NULL, false )
    add_integer( "key-length", SRT_DEFAULT_KEY_LENGTH,
            SRT_KEY_LENGTH_TEXT, SRT_KEY_LENGTH_TEXT, false )
        change_integer_list( srt_key_lengths, srt_key_length_names )

    set_capability( "sout access", 0 )
    add_shortcut( "srt" )

    set_callbacks( Open, Close )
vlc_module_end ()
