/*
 * Table Print utilities
 * Copyright (C) 2012-2013 Paul Ionkin <paul.ionkin@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */
#include "tprint.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib/gprintf.h>

struct _TPrint {
    char * buff;
	int buff_len;
	int * buff_off;
    GList *l_columns;
    gint rows;
	gint min_rows;

    gchar *fmt_int32;
    gchar *fmt_uint64;
    gchar *fmt_str;
    gchar *fmt_double;

    gboolean borders;
    gint spaces_left;
    gint spaces_between;
    gboolean show_header;
};

typedef struct  {
    gchar *caption;
    gint max_width;
    TPrintAlign caption_align;
    TPrintAlign data_align;
    GList *l_data; // list of strings
} TPrintColumn;

static void tprint_column_free (TPrintColumn *col);

TPrint *tprint_create (gchar * buff, gint buff_len, gint * buff_off, gboolean borders, gboolean show_header, gint spaces_left, gint spaces_between, gint min_rows)
{
    TPrint *tprint;

    tprint = g_new0 (TPrint, 1);
    tprint->l_columns = NULL;
    tprint->buff = buff;
	tprint->buff_len = buff_len;
	tprint->buff_off = buff_off;
    tprint->borders = borders;
    tprint->spaces_left = spaces_left;
    tprint->spaces_between = spaces_between;
    tprint->rows = 0;
    tprint->show_header = show_header;
	tprint->min_rows = min_rows;

    tprint->fmt_int32 = g_strdup ("%d");
    tprint->fmt_uint64 = g_strdup ("%lu");
    tprint->fmt_str = g_strdup ("%s");
    tprint->fmt_double = g_strdup ("%0.3f");

    return tprint;
}

void tprint_free (TPrint *tprint)
{
    GList *l;

    g_free (tprint->fmt_int32);
    g_free (tprint->fmt_uint64);
    g_free (tprint->fmt_str);
    g_free (tprint->fmt_double);

    for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
        TPrintColumn *col = (TPrintColumn *) l->data;
        tprint_column_free (col);
    }
    g_list_free (tprint->l_columns);
    g_free (tprint);
}

void tprint_set_double_fmt (TPrint *tprint, const gchar *fmt)
{
    if (tprint->fmt_double)
        g_free (tprint->fmt_double);
    tprint->fmt_double = g_strdup (fmt);
}

void tprint_set_int32_fmt (TPrint *tprint, const gchar *fmt)
{
    if (tprint->fmt_int32)
        g_free (tprint->fmt_int32);
    tprint->fmt_int32 = g_strdup (fmt);
}

static void column_add_str (TPrintColumn *column, gchar *str)
{
    if (column->max_width < (gint)strlen (str))
        column->max_width = (gint)strlen (str);

    column->l_data = g_list_append (column->l_data, str);
}

void tprint_column_add (TPrint *tprint, const gchar *caption, TPrintAlign caption_align, TPrintAlign data_align)
{
    TPrintColumn *col;

    col = g_new0 (TPrintColumn, 1);
    if (tprint->show_header) {
        col->caption = g_strdup (caption);
        col->max_width = strlen (caption);
    } else {
        col->caption = NULL;
        col->max_width = 0;
    }
    col->caption_align = caption_align;
    col->data_align = data_align;
    col->l_data = NULL;

    tprint->l_columns = g_list_append (tprint->l_columns, col);
}

static void tprint_column_free (TPrintColumn *col)
{
    GList *l;
    
    for (l = g_list_first (col->l_data); l; l = g_list_next (l)) {
        gchar *str = (gchar *) l->data;
        g_free (str);
    }
    g_list_free (col->l_data);
    if (col->caption)
        g_free (col->caption);
    g_free (col);
}

// convert data to string
void tprint_data_add_int32 (TPrint *tprint, gint col, gint32 data)
{
    TPrintColumn *column;
    gchar *str;

    column = (TPrintColumn *) g_list_nth_data (tprint->l_columns, col);
    if (!column)
        return;
    str = g_strdup_printf (tprint->fmt_int32, data);
    column_add_str (column, str);
}

void tprint_data_add_uint64 (TPrint *tprint, gint col, guint64 data)
{
    TPrintColumn *column;
    gchar *str;

    column = (TPrintColumn *) g_list_nth_data (tprint->l_columns, col);
    if (!column)
        return;
    str = g_strdup_printf (tprint->fmt_uint64, data);
    column_add_str (column, str);
}

void tprint_data_add_str (TPrint *tprint, gint col, const gchar *data)
{
    TPrintColumn *column;
    gchar *str;

    column = (TPrintColumn *) g_list_nth_data (tprint->l_columns, col);
    if (!column)
        return;
    str = g_strdup_printf (tprint->fmt_str, data);
    column_add_str (column, str);
}

void tprint_data_add_double (TPrint *tprint, gint col, gdouble data)
{
    TPrintColumn *column;
    gchar *str;

    column = (TPrintColumn *) g_list_nth_data (tprint->l_columns, col);
    if (!column)
        return;
    str = g_strdup_printf (tprint->fmt_double, data);
    column_add_str (column, str);
}

#define  P(format_, ...) *(tprint->buff_off) += g_snprintf(tprint->buff + (*tprint->buff_off), tprint->buff_len - (*tprint->buff_off), format_, ##__VA_ARGS__)
static void tprint_print_no_borders (TPrint *tprint)
{
    GList *l;
    gint row;
    gboolean first = TRUE;
    gint spaces_left;

    if (tprint->show_header) {
        for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
            TPrintColumn *col = (TPrintColumn *) l->data;

            if (first) {
                spaces_left = tprint->spaces_left;
                first = FALSE;
            } else
                spaces_left = tprint->spaces_between;
            
            if (col->caption_align == TPAlign_left) {
				P("%*s%-*s", 
                    spaces_left, "",
                    col->max_width, col->caption
                );
            } else if (col->caption_align == TPAlign_center) {
				P("%*s%-*s", 
                	spaces_left + (col->max_width - (gint)strlen (col->caption)) / 2, "",
                    col->max_width - (col->max_width - (gint)strlen (col->caption)) / 2, col->caption
                    );
            } else {
				P("%*s%*s", 
                	spaces_left, "",
                    col->max_width, col->caption
                );
            }

            if (tprint->rows < (gint)g_list_length (col->l_data))
                tprint->rows = (gint)g_list_length (col->l_data);

        }
		P("\n");
    } else {

        for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
            TPrintColumn *col = (TPrintColumn *) l->data;
            if (tprint->rows < (gint)g_list_length (col->l_data))
                tprint->rows = (gint)g_list_length (col->l_data);
        }        
    }

    for (row = 0; row < tprint->rows; row++) {
        first = TRUE;
        for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
            TPrintColumn *col = (TPrintColumn *) l->data;
            gchar *cell = (gchar *) g_list_nth_data (col->l_data, row);
            if (first) {
                spaces_left = tprint->spaces_left;
                first = FALSE;
            } else 
                spaces_left = tprint->spaces_between;

            if (col->data_align == TPAlign_left) {
				P("%*s%-*s", 
                    spaces_left, "",
                    col->max_width, cell
                );
            } else if (col->data_align == TPAlign_center) {
				P("%*s%-*s", 
                    spaces_left + (col->max_width - (gint)strlen (cell)) / 2, "",
                    col->max_width - (col->max_width - (gint)strlen (cell)) / 2, cell
                );
            } else {
                P("%*s%*s", 
                    spaces_left, "",
                    col->max_width, cell
                );
            }
        }
		P("\n");
    }
	
	for (; row < tprint->min_rows; row++) {
		for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
			TPrintColumn *col = (TPrintColumn *) l->data;
			P("%*s%-*s", spaces_left, "", col->max_width, " ");
		}
		P("\n");
	}
}

static void tprint_print_with_borders (TPrint *tprint)
{
    GList *l;
    gint row;
    gboolean first = TRUE;
    gint spaces_left;
    gint full_width = 0;
    gchar *str;
    gint i;

    if (tprint->borders) {
        for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
            TPrintColumn *col = (TPrintColumn *) l->data;
            full_width += (col->max_width + tprint->spaces_between);
        }
    }

    full_width += g_list_length (tprint->l_columns);
    full_width -= 1;


    if (tprint->show_header) {
        str = g_new0 (gchar, full_width + 1);
        for (i = 0; i < full_width; i++)
            str[i] = '=';
        str[i] = '\0';

        P("%*s%s\n", 
            tprint->spaces_left + 1, "",
            str
        );
        g_free (str);

        P("%*s", tprint->spaces_left, "");
        for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
            TPrintColumn *col = (TPrintColumn *) l->data;

            if (first) {
                first = FALSE;
            } else {
            }
            spaces_left = tprint->spaces_between;
            
            if (col->caption_align == TPAlign_left) {
                P("|%*s%-*s%*s", 
                    spaces_left / 2, "",
                    col->max_width, col->caption,
                    spaces_left / 2, ""
                );
            } else if (col->caption_align == TPAlign_center) {
                P("|%*s%s%*s", 
                    spaces_left / 2 +  (col->max_width - (gint)strlen (col->caption)) / 2, "",
                    col->caption,
                    col->max_width - (gint)strlen (col->caption) - (col->max_width - (gint)strlen (col->caption)) / 2 + spaces_left / 2, ""
                );
            } else {
                P("|%*s%*s%*s", 
                    spaces_left / 2, "",
                    col->max_width, col->caption,
                    spaces_left / 2, ""
                );
            }

            if (tprint->rows < (gint)g_list_length (col->l_data))
                tprint->rows = (gint)g_list_length (col->l_data);

        }
        P("|\n");
    } else {

        for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
            TPrintColumn *col = (TPrintColumn *) l->data;
            if (tprint->rows < (gint)g_list_length (col->l_data))
                tprint->rows = (gint)g_list_length (col->l_data);
        }        
    }

    str = g_new0 (gchar, full_width + 1);
    for (i = 0; i < full_width; i++)
        str[i] = '=';
    str[i] = '\0';

    P("%*s%s\n", 
        tprint->spaces_left + 1, "",
        str
    );
    g_free (str);

    for (row = 0; row < tprint->rows; row++) {
        P("%*s", tprint->spaces_left, "");
        for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
            TPrintColumn *col = (TPrintColumn *) l->data;
            gchar *cell = (gchar *) g_list_nth_data (col->l_data, row);
            if (first) {
                first = FALSE;
            } else {
            }
            
            spaces_left = tprint->spaces_between;

            if (col->data_align == TPAlign_left) {
                P("|%*s%-*s%*s", 
                    spaces_left / 2, "",
                    col->max_width, cell,
                    spaces_left / 2, ""
                );
            } else if (col->data_align == TPAlign_center) {
				P("|%*s%s%*s", 
                    spaces_left / 2 +  (col->max_width - (gint)strlen (cell)) / 2, "",
                    cell,
                    col->max_width - (gint)strlen (cell) - (col->max_width - (gint)strlen (cell)) / 2 + spaces_left / 2, ""
                );
            } else {
                P("|%*s%*s%*s", 
                    spaces_left / 2, "",
                    col->max_width, cell,
                    spaces_left / 2, ""
                );
            }
        }
        P("|\n");
    }

	for (; row < tprint->min_rows; row++) {
		P("%*s", tprint->spaces_left, "");
		spaces_left = tprint->spaces_between;
		for (l = g_list_first (tprint->l_columns); l; l = g_list_next (l)) {
			TPrintColumn *col = (TPrintColumn *) l->data;
			P("|%*s%-*s%*s", 
                    spaces_left / 2, "", col->max_width, " ", spaces_left / 2, "");
		}
		P("|\n");
	}

    str = g_new0 (gchar, full_width + 1);
    for (i = 0; i < full_width; i++)
        str[i] = '=';
    str[i] = '\0';

    P("%*s%s\n", 
        tprint->spaces_left + 1, "",
        str
    );
    g_free (str);
}

void tprint_print (TPrint *tprint)
{ 
    if (tprint->borders)
        tprint_print_with_borders (tprint);
    else
        tprint_print_no_borders (tprint);
	/*
	uncomment when you want line space between tables
	P("\n");
	*/
}
