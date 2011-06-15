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
static struct WatchInfo *watchInfoListHead = NULL;
static struct WatchInfo *watchInfoListTail = NULL;
static struct Expression *faultyExpression = NULL;

struct Expression
{
  struct Expression *next;
  struct Expression *prev;
  const char *expressionSyntax;
  const char *expressionValue;
  int lineNo;
};

struct WatchInfo
{
	struct WatchInfo *next;
	struct WatchInfo *prev;
	int hitNumber;
	const char *value;
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
wait_for_stop (struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
  while (!mi_get_response (cntxt->gdb_handle))
    usleep (1000);
  /* The end of the async. */
  cntxt->gdb_stop_reason = mi_res_stop (cntxt->gdb_handle);
  if (cntxt->gdb_stop_reason)
    {
      if (cntxt->gdb_stop_reason->reason == sr_exited_normally)
    	  return GDB_STATE_EXIT_NORMALLY;
      else if (cntxt->gdb_stop_reason->reason == sr_bkpt_hit) {
    	  /* We want to inspect an expression */
    	  /* Set hardware watch at the expression to inspect */
		  mi_wp *wp = gmi_break_watch(cntxt->gdb_handle, wm_write, cntxt->inspect_expression);
		  if (NULL == wp)
			{
			 printf("Error in setting a watchpoint at expression:%s\n", cntxt->inspect_expression);
			 return GDB_STATE_ERROR;
			}
		  mi_free_wp(wp);
		  /* continue execution */
		  gmi_exec_continue(cntxt->gdb_handle);
		  return wait_for_stop (cntxt);
      }
      else if (cntxt->gdb_stop_reason->reason == sr_wp_trigger) {
    	  static int watchPointHitNumber = 0;
    	  struct WatchInfo *watchInfo = GNUNET_malloc(sizeof(struct WatchInfo));
    	  watchInfo->hitNumber = ++watchPointHitNumber;
    	  watchInfo->value = cntxt->gdb_stop_reason->wp_val;
    	  GNUNET_CONTAINER_DLL_insert(watchInfoListHead, watchInfoListTail, watchInfo);
    	  if (watchPointHitNumber == 1023)
    		  printf("HEY! 1023! WE ARE GETTING OUT OF THE LOOP!\n");
    	  gmi_exec_continue(cntxt->gdb_handle);
    	  return wait_for_stop (cntxt);
      }
      else if (cntxt->gdb_stop_reason->reason == sr_wp_scope) {
    	  gmi_exec_continue(cntxt->gdb_handle);
    	  return wait_for_stop (cntxt);
      }
      cntxt->gdb_frames = gmi_stack_info_frame (cntxt->gdb_handle);
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
      /* Change current GDB frame to the one containing source code */
      gmi_stack_select_frame(cntxt->gdb_handle, cntxt->gdb_frames->level);

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
  struct Expression *tmp;


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
  faultyExpression = getFaultyExpression (cntxt);


  if (NULL != faultyExpression)
    {
      tmp = expressionListHead;
      while (NULL != tmp)
	{
	  const char *eval;
	      eval =
		gmi_data_evaluate_expression (cntxt->gdb_handle,
					      tmp->expressionSyntax);
	      if (NULL != eval) {
			  tmp->expressionValue = eval;
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


  if (strcasecmp (signalMeaning, "Segmentation fault") == 0)
    {
      cntxt->bug_detected = BUG_NULL_POINTER;
      GNUNET_MONKEY_EDB_get_expressions (edbCntxt,
     					   cntxt->gdb_frames->file,
     					   cntxt->gdb_frames->line, endScope,
     					   &iterateExpressions, NULL);
      ret = analyzeSegmentationFault (cntxt);
    }
  else if (strcasecmp (signalMeaning, "Aborted") == 0)
    {
      cntxt->bug_detected = BUG_CUSTOM;
      GNUNET_MONKEY_EDB_get_sub_expressions (edbCntxt,
       					   cntxt->gdb_frames->file,
       					   cntxt->gdb_frames->line, endScope,
       					   &iterateExpressions, NULL);
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
  char *valgrindCommand;
  FILE *valgrindPipe;

  GNUNET_asprintf(&cntxt->valgrind_output_tmp_file_name, "%d", rand());
  cntxt->debug_mode = DEBUG_MODE_VALGRIND;
  GNUNET_asprintf (&valgrindCommand, "valgrind --leak-check=yes --log-file=%s %s",
		   cntxt->valgrind_output_tmp_file_name, cntxt->binary_name);
  valgrindPipe = popen (valgrindCommand, "r");
  if (NULL == valgrindPipe)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error in running Valgrind!\n");
      GNUNET_free (valgrindCommand);
      return GNUNET_NO;
    }

  pclose(valgrindPipe);
  GNUNET_free(valgrindCommand);
  return GNUNET_OK;
}


int
GNUNET_MONKEY_ACTION_rerun_with_gdb (struct GNUNET_MONKEY_ACTION_Context
				     *cntxt)
{
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

  if ((NULL != cntxt->inspect_expression) && (NULL != cntxt->inspect_function))
    {
	  /* Setting a breakpoint at the function containing the expression to inspect */
	  mi_bkpt *bp = gmi_break_insert_full(cntxt->gdb_handle, 0, 0, NULL, -1, -1, cntxt->inspect_function);
	  if (NULL == bp)
	    {
	     printf("Error setting breakpoint at function:%s\n", cntxt->inspect_function);
	     mi_disconnect(cntxt->gdb_handle);
	     return GNUNET_NO;
	    }
	  mi_free_bkpt(bp);
    }

  /* Run the program. */
  if (!gmi_exec_run (cntxt->gdb_handle))
    {
      printf ("Error in run!\n");
      mi_disconnect (cntxt->gdb_handle);
      return GNUNET_NO;
    }
  /* Here we should be stopped when the program crashes */
  ret = wait_for_stop (cntxt);
  if (ret == GDB_STATE_ERROR)
    mi_disconnect (cntxt->gdb_handle);

  return ret;
}


static int
getExpressionListSize(struct Expression *head)
{
	int size, count = 0;
	struct Expression *tmp = head;

	while (NULL != tmp) {
		count++;
		tmp = tmp->next;
	}
	/* Since the faulty expression is the longest in the expression list */
	size = count * strlen(faultyExpression->expressionSyntax) * sizeof(char);
	return size;
}


static const char *
expressionListToString (struct Expression *head)
{
  char *string = GNUNET_malloc (getExpressionListSize(head));
  char *strTmp;
  struct Expression *tmp = head;

  GNUNET_asprintf (&strTmp, "%s = %s\n", tmp->expressionSyntax, NULL == tmp->expressionValue ? "Not evaluated" : tmp->expressionValue);
  strcpy (string, strTmp);
  GNUNET_free (strTmp);
  tmp = tmp->next;

  while (NULL != tmp)
    {
      GNUNET_asprintf (&strTmp, "%s = %s\n", tmp->expressionSyntax, NULL == tmp->expressionValue ? "Not evaluated" : tmp->expressionValue);
      strcat (string, strTmp);
      GNUNET_free (strTmp);
      tmp = tmp->next;
    }
  return string;
}

#if 0
static int
getWatchInfoListSize(struct WatchInfo *head)
{
	int count = 0;
	int largestStr = 0;
	struct WatchInfo *tmp = head;

	while (NULL != tmp) {
		if (largestStr < strlen(tmp->value))
			largestStr = strlen(tmp->value);
		tmp = tmp->next;
		count++;
	}

	return count * largestStr;
}

static const char*
watchInfoListToString(struct WatchInfo *head)
{
	char *string = GNUNET_malloc(getWatchInfoListSize(head));
	char *strTmp;
	struct WatchInfo *tmp = head;

	GNUNET_asprintf (&strTmp, "%s\t \t%s\n", tmp->hitNumber, tmp->value);
	strcpy (string, strTmp);
	GNUNET_free (strTmp);
	tmp = tmp->next;

	while (NULL != tmp) {
		GNUNET_asprintf (&strTmp, "%s\t \t%s\n", tmp->hitNumber, tmp->value);
		strcat (string, strTmp);
		GNUNET_free(strTmp);
		tmp = tmp->next;
	}

	return string;
}
#endif

static const char* getValgrindOutput(struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
	char* valgrindOutput;
	int size;
	FILE *valgrindFile = fopen(cntxt->valgrind_output_tmp_file_name, "r");
	fseek(valgrindFile, 0L, SEEK_END);
	size = ftell(valgrindFile);
	fseek(valgrindFile, 0L, SEEK_SET);

	valgrindOutput = GNUNET_malloc(size);
	fread(valgrindOutput, size - 1, 1, valgrindFile);
	fclose(valgrindFile);
	return valgrindOutput;
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
		  const char *expToString = expressionListToString(expressionListHead);
	      GNUNET_asprintf (&(cntxt->debug_report),
			       "Bug detected in file:%s\nfunction:%s\nline:%d\nreceived signal:%s\n%s\nDetails:\nAssertion Failure\nExpression evaluation:\n%s\n",
			       cntxt->gdb_frames->file,
			       cntxt->gdb_frames->func,
			       cntxt->gdb_frames->line,
			       cntxt->gdb_stop_reason->signal_name,
			       cntxt->gdb_stop_reason->signal_meaning,
			       expToString);
	    }
	  else
	    {
	      /* Inspection of user-defined expression */
		  /*
	      GNUNET_asprintf(&(cntxt->debug_report),
	    		  "Inspection of expression: %s in function: %s, file:%s\nHit Number: \t \tValue:\n%s",
	    		  cntxt->inspect_expression, cntxt->inspect_function, cntxt->binary_name, watchInfoListToString(watchInfoListHead));
	    		  */
	    }
	}
      break;
    case DEBUG_MODE_VALGRIND:
      GNUNET_asprintf (&(cntxt->debug_report),
		       "Bug detected in file:%s\nfunction:%s\nline:%d\nreceived signal:%s\n%s\n Details:\n Memory Check from Valgrind:\n%s",
		       cntxt->gdb_frames->file, cntxt->gdb_frames->func,
		       cntxt->gdb_frames->line,
		       cntxt->gdb_stop_reason->signal_name,
		       cntxt->gdb_stop_reason->signal_meaning,
		       getValgrindOutput(cntxt));
      break;
    default:
      break;
    }

  cntxt->debug_mode = DEBUG_MODE_REPORT_READY;
  return GNUNET_OK;
}


int
GNUNET_MONKEY_ACTION_delete_context(struct GNUNET_MONKEY_ACTION_Context *cntxt)
{
	if (NULL != cntxt->debug_report)
		GNUNET_free(cntxt->debug_report);
	if (NULL != cntxt->valgrind_output_tmp_file_name) {
		remove(cntxt->valgrind_output_tmp_file_name);
		GNUNET_free(cntxt->valgrind_output_tmp_file_name);
	}

	GNUNET_free(cntxt);
	return GNUNET_OK;
}


int
GNUNET_MONKEY_ACTION_check_bug_redundancy ()
{
  return GNUNET_OK;
}
