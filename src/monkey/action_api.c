/*
     This file is part of GNUnet.
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file monkey/action_api.c
 * @brief Monkey API for actions taken by Monkey while debugging
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_monkey_action.h"
#include "gnunet_monkey_edb.h"
#include "gnunet_container_lib.h"
#include <libesmtp.h>

extern void sendMail (const char *messageContents, const char *emailAddress);


static int async_c = 0;
static struct Expression *expressionListHead = NULL;
static struct Expression *expressionListTail = NULL;

struct Expression
{
  struct Expression *next;
  struct Expression *prev;
  const char *expressionSyntax;
  int lineNo;
};

static void
cb_console (const char *str, void *data)
{
  printf ("CONSOLE> %s\n", str);
}


/* Note that unlike what's documented in gdb docs it isn't usable. */
static void
cb_target (const char *str, void *data)
{
  printf ("TARGET> %s\n", str);
}


static void
cb_log (const char *str, void *data)
{
  printf ("LOG> %s\n", str);
}


static void
cb_to (const char *str, void *data)
{
  printf (">> %s", str);
}


static void
cb_from (const char *str, void *data)
{
  printf ("<< %s\n", str);
}


static void
cb_async (mi_output * o, void *data)
{
  printf ("ASYNC\n");
  async_c++;
}


static int
wait_for_stop (mi_h * h, struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
  while (!mi_get_response (h))
    usleep (1000);
  /* The end of the async. */
  cntxt->gdb_stop_reason = mi_res_stop (h);
  if (cntxt->gdb_stop_reason)
    {
      if (cntxt->gdb_stop_reason->reason == sr_exited_normally)
	return GDB_STATE_EXIT_NORMALLY;

      cntxt->gdb_frames = gmi_stack_info_frame (h);
      if (NULL == cntxt->gdb_frames)
	GNUNET_break (0);

      if (0 == cntxt->gdb_frames->line)
	{
	  /*
	   * This happens if the program stops in a shared library (inner frames)
	   * We will move to outer frames until reaching the faulty line in the source code
	   */
	  cntxt->gdb_frames = gmi_stack_list_frames (cntxt->gdb_handle);
	  do
	    {
	      cntxt->gdb_frames = cntxt->gdb_frames->next;
	    }
	  while (0 == cntxt->gdb_frames->line);
	}

      return GDB_STATE_STOPPED;
    }
  return GDB_STATE_ERROR;
}


int
GNUNET_MONKEY_ACTION_report_file (struct GNUNET_MONKEY_ACTION_Context *cntxt,
				  const char *dumpFileName)
{
  FILE *file = fopen (dumpFileName, "w");
  GNUNET_assert (NULL != file);
  fprintf (file, "%s", cntxt->debug_report);
  fclose (file);
  return GNUNET_OK;
}


int
GNUNET_MONKEY_ACTION_report_email (struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
  if (cntxt->debug_mode == DEBUG_MODE_REPORT_READY)
    sendMail (cntxt->debug_report, cntxt->email_address);

  return GNUNET_OK;
}


static int
iterateExpressions (void *cls, int numColumns, char **colValues,
		    char **colNames)
{
  struct Expression *expression;

  if (NULL == colValues[0] || NULL == colValues[1])
    return 1;			/* Error */

  expression = GNUNET_malloc (sizeof (struct Expression));
  expression->expressionSyntax = strdup (colValues[0]);
  expression->lineNo = atoi (colValues[1]);

  printf ("Inserting expression:%s", expression->expressionSyntax);
  GNUNET_CONTAINER_DLL_insert (expressionListHead, expressionListTail,
			       expression);

  return 0;			/* OK */
}


static int
scopeEndCallback (void *cls, int numColumns, char **colValues,
		  char **colNames)
{
  int *scopeEnd = (int *) cls;

  *scopeEnd = atoi (colValues[0]);
  if (*scopeEnd < 0)
    return 1;			/* Error */
  return 0;
}


static struct Expression *
getFaultyExpression (struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
  struct Expression *faultyExpression = NULL;
  struct Expression *tmp = NULL;
  int expressionLength = 0;

  tmp = expressionListHead;
  while (NULL != tmp)
    {
      if ((tmp->lineNo == cntxt->gdb_frames->line)
	  && (strlen (tmp->expressionSyntax) > expressionLength))
	{
	  expressionLength = strlen (tmp->expressionSyntax);
	  faultyExpression = tmp;
	}
      tmp = tmp->next;
    }

  return faultyExpression;
}

static int
analyzeSegmentationFault (struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
  struct Expression *faultyExpression = NULL;
  struct Expression *tmp;
  int expressionLength = 0;


  faultyExpression = getFaultyExpression (cntxt);

  if (NULL != faultyExpression)
    {
      tmp = expressionListHead;
      while (NULL != tmp)
	{
	  const char *eval;
	  if (tmp != faultyExpression)
	    {
	      eval =
		gmi_data_evaluate_expression (cntxt->gdb_handle,
					      tmp->expressionSyntax);
	      if (NULL != eval
		  && (strcmp (eval, "0x0") == 0
		      || strcmp (eval, "NULL") == 0))
		{
		  cntxt->gdb_null_variable = tmp->expressionSyntax;
		  return GNUNET_OK;
		}
	    }
	  tmp = tmp->next;
	}
    }
  /* Set watch points on the faulty-expression's subexpressions */
//      if (NULL != faultyExpression) {
//              tmp = expressionListHead;
//              while (NULL != tmp) {
//                      if (tmp != faultyExpression) {
//                              /* Only subexpressions are interesting */
//                               watchPoint = gmi_break_watch(cntxt->gdb_handle, wm_write, tmp->expressionSyntax);
//                               if (!watchPoint)
//                                 {
//                                      printf("Error in setting watchpoint\n");
//                                      return 1;
//                                 }
//                               printf("Watchpoint %d for expression: %s\n", watchPoint->number, watchPoint->exp);
//                               mi_free_wp(watchPoint);
//                      }
//                      tmp = tmp->next;
//              }
//              return GNUNET_OK;
//      }
  return GDB_STATE_ERROR;
}



static int
analyzeCustomFault (struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
  struct Expression *tmp;
  struct Expression *faultyExpression = getFaultyExpression (cntxt);
  struct Variable *variable;
  if (NULL != faultyExpression)
    {
      tmp = expressionListHead;
      while (NULL != tmp)
	{
	  const char *eval;
	  if (tmp != faultyExpression)
	    {
	      eval =
		gmi_data_evaluate_expression (cntxt->gdb_handle,
					      tmp->expressionSyntax);
	      variable = GNUNET_malloc (sizeof (struct Variable));
	      variable->name = tmp->expressionSyntax;
	      variable->value = eval;
	      GNUNET_CONTAINER_DLL_insert (cntxt->variable_list_head,
					   cntxt->variable_list_tail,
					   variable);
	    }
	  tmp = tmp->next;
	}
    }
  return GNUNET_OK;
}


int
GNUNET_MONKEY_ACTION_inspect_expression_database (struct
						  GNUNET_MONKEY_ACTION_Context
						  *cntxt)
{
  struct GNUNET_MONKEY_EDB_Context *edbCntxt;
  int ret = GNUNET_OK;
  int endScope;
  const char *signalMeaning = cntxt->gdb_stop_reason->signal_meaning;

  edbCntxt = GNUNET_MONKEY_EDB_connect (cntxt->expression_database_path);
  if (NULL == edbCntxt)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Unable to connect to Expression Database file!\n");
      return GNUNET_NO;
    }

  ret = GNUNET_MONKEY_EDB_get_expression_scope_end (edbCntxt,
						    cntxt->gdb_frames->file,
						    cntxt->gdb_frames->line,
						    &scopeEndCallback,
						    &endScope);
  if (endScope < 0)
    return GNUNET_NO;

  ret = GNUNET_MONKEY_EDB_get_expressions (edbCntxt,
					   cntxt->gdb_frames->file,
					   cntxt->gdb_frames->line, endScope,
					   &iterateExpressions, NULL);

  if (strcasecmp (signalMeaning, "Segmentation fault") == 0)
    {
      cntxt->bug_detected = BUG_NULL_POINTER;
      ret = analyzeSegmentationFault (cntxt);
    }
  else if (strcasecmp (signalMeaning, "Aborted") == 0)
    {
      cntxt->bug_detected = BUG_CUSTOM;
      ret = analyzeCustomFault (cntxt);
    }

  GNUNET_MONKEY_EDB_disconnect (edbCntxt);
  mi_disconnect (cntxt->gdb_handle);
  return ret;
}


int
GNUNET_MONKEY_ACTION_rerun_with_valgrind (struct GNUNET_MONKEY_ACTION_Context
					  *cntxt)
{
  FILE *valgrindPipe;
  int size;
  char *valgrindCommand;
  cntxt->debug_mode = DEBUG_MODE_VALGRIND;
  GNUNET_asprintf (&valgrindCommand, "valgrind --leak-check=yes %s",
		   cntxt->binary_name);
  valgrindPipe = popen (valgrindCommand, "r");
  if (NULL == valgrindPipe)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error in running Valgrind!\n");
      GNUNET_free (valgrindCommand);
      return GNUNET_NO;
    }

  fscanf (valgrindPipe, "%d", &size);

  /* Read Valgrind stream */
  cntxt->valgrind_output = GNUNET_malloc (size);
  fscanf (valgrindPipe, "%s", cntxt->valgrind_output);
  GNUNET_free (valgrindCommand);
  if (0 != pclose (valgrindPipe))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Error while closing Valgrind pipe!\n");
      return GNUNET_NO;
    }
  return GNUNET_OK;
}


int
GNUNET_MONKEY_ACTION_rerun_with_gdb (struct GNUNET_MONKEY_ACTION_Context
				     *cntxt)
{
  mi_wp *watchPoint;
  cntxt->debug_mode = DEBUG_MODE_GDB;
  /* This is like a file-handle for fopen.
     Here we have all the state of gdb "connection". */
  if (NULL != cntxt->gdb_binary_path)
    mi_set_gdb_exe (cntxt->gdb_binary_path);
  int ret;

  /* Connect to gdb child. */
  cntxt->gdb_handle = mi_connect_local ();
  if (!cntxt->gdb_handle)
    {
      printf ("Connect failed\n");
      return GNUNET_NO;
    }
  printf ("Connected to gdb!\n");

  /* Set all callbacks. */
  mi_set_console_cb (cntxt->gdb_handle, cb_console, NULL);
  mi_set_target_cb (cntxt->gdb_handle, cb_target, NULL);
  mi_set_log_cb (cntxt->gdb_handle, cb_log, NULL);
  mi_set_async_cb (cntxt->gdb_handle, cb_async, NULL);
  mi_set_to_gdb_cb (cntxt->gdb_handle, cb_to, NULL);
  mi_set_from_gdb_cb (cntxt->gdb_handle, cb_from, NULL);

  /* Set the name of the child and the command line arguments. */
  if (!gmi_set_exec (cntxt->gdb_handle, cntxt->binary_name, NULL))
    {
      printf ("Error setting exec y args\n");
      mi_disconnect (cntxt->gdb_handle);
      return GNUNET_NO;
    }

  /* Tell gdb to attach the child to a terminal. */
  if (!gmi_target_terminal (cntxt->gdb_handle, ttyname (STDIN_FILENO)))
    {
      printf ("Error selecting target terminal\n");
      mi_disconnect (cntxt->gdb_handle);
      return GNUNET_NO;
    }

  if (NULL != cntxt->inspect_expression)
    {
      watchPoint =
	gmi_break_watch (cntxt->gdb_handle, wm_write,
			 cntxt->inspect_expression);
      if (NULL == watchPoint)
	{
	  printf ("Error in setting watch point\n");
	  mi_disconnect (cntxt->gdb_handle);
	  return GNUNET_NO;
	}
    }

  /* Run the program. */
  if (!gmi_exec_run (cntxt->gdb_handle))
    {
      printf ("Error in run!\n");
      mi_disconnect (cntxt->gdb_handle);
      return GNUNET_NO;
    }
  /* Here we should be stopped when the program crashes */
  ret = wait_for_stop (cntxt->gdb_handle, cntxt);
  if (ret == GDB_STATE_ERROR)
    mi_disconnect (cntxt->gdb_handle);

  return ret;
}

static const char *
variableListToString (struct Variable *head)
{
  const char *string = GNUNET_malloc (200 * sizeof (char));
  const char *strTmp;
  struct Variable *tmp = head;
  asprintf (&strTmp, "%s = %s\n", tmp->name, tmp->value);
  strcpy (string, strTmp);
  free (strTmp);
  while (NULL != tmp)
    {
      asprintf (&strTmp, "%s = %s\n", tmp->name, tmp->value);
      strcat (string, strTmp);
      free (strTmp);
      tmp = tmp->next;
    }
  return string;
}


int
GNUNET_MONKEY_ACTION_format_report (struct GNUNET_MONKEY_ACTION_Context
				    *cntxt)
{
  switch (cntxt->debug_mode)
    {
    case DEBUG_MODE_GDB:
      if (cntxt->bug_detected == BUG_NULL_POINTER)
	{
	  GNUNET_asprintf (&(cntxt->debug_report),
			   "Bug detected in file:%s\nfunction:%s\nline:%d\nreason:%s\nreceived signal:%s\n%s\n Details:\n Expression:%s is NULL\n",
			   cntxt->gdb_frames->file, cntxt->gdb_frames->func,
			   cntxt->gdb_frames->line,
			   mi_reason_enum_to_str (cntxt->gdb_stop_reason->
						  reason),
			   cntxt->gdb_stop_reason->signal_name,
			   cntxt->gdb_stop_reason->signal_meaning,
			   cntxt->gdb_null_variable);
	}
      else if (cntxt->bug_detected == BUG_CUSTOM)
	{
	  if (NULL == cntxt->inspect_expression)
	    {
	      /* Assertion Failure */
	      GNUNET_asprintf (&(cntxt->debug_report),
			       "Bug detected in file:%s\nfunction:%s\nline:%d\nreason:%s\nreceived signal:%s\n%s\n Details:\n Assertion Failure\n Expression evaluation:\n",
			       cntxt->gdb_frames->file,
			       cntxt->gdb_frames->func,
			       cntxt->gdb_frames->line,
			       mi_reason_enum_to_str (cntxt->gdb_stop_reason->
						      reason),
			       cntxt->gdb_stop_reason->signal_name,
			       cntxt->gdb_stop_reason->signal_meaning,
			       variableListToString (cntxt->
						     variable_list_head));
	    }
	  else
	    {
	      /* Failure in a user-defined expression */
	      GNUNET_asprintf (&(cntxt->debug_report),
			       "Bug detected in file:%s\nfunction:%s\nline:%d\nreason:%s\nreceived signal:%s\n%s\n Details:\n Failure in user-defined expression:%s\n Expression evaluation:\n",
			       cntxt->gdb_frames->file,
			       cntxt->gdb_frames->func,
			       cntxt->gdb_frames->line,
			       mi_reason_enum_to_str (cntxt->gdb_stop_reason->
						      reason),
			       cntxt->gdb_stop_reason->signal_name,
			       cntxt->gdb_stop_reason->signal_meaning,
			       cntxt->inspect_expression,
			       variableListToString (cntxt->
						     variable_list_head));
	    }
	}
      break;
    case DEBUG_MODE_VALGRIND:
      GNUNET_asprintf (&(cntxt->debug_report),
		       "Bug detected in file:%s\nfunction:%s\nline:%d\nreason:%s\nreceived signal:%s\n%s\n Details:\n Memory Check from Valgrind:%s\n",
		       cntxt->gdb_frames->file, cntxt->gdb_frames->func,
		       cntxt->gdb_frames->line,
		       mi_reason_enum_to_str (cntxt->gdb_stop_reason->reason),
		       cntxt->gdb_stop_reason->signal_name,
		       cntxt->gdb_stop_reason->signal_meaning,
		       cntxt->valgrind_output);
      break;
    default:
      break;
    }

  cntxt->debug_mode = DEBUG_MODE_REPORT_READY;
  return GNUNET_OK;
}


int
GNUNET_MONKEY_ACTION_check_bug_redundancy ()
{
  return GNUNET_OK;
}
