/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/per_transport_ats.c
 * @brief testcase for ats functionality
 */
#include "platform.h"
#include "gnunet_time_lib.h"
#include "gauger.h"
#if HAVE_LIBGLPK
#include <glpk.h>
#endif

#define VERBOSE GNUNET_NO

#define EXECS 5


#if HAVE_LIBGLPK
static int executions = EXECS;
static uint64_t exec_time[EXECS];

static uint64_t sim_no_opt_avg;
static uint64_t sim_with_opt_avg;
static uint64_t mlp_no_opt_avg;
static uint64_t mlp_with_opt_avg;

static glp_prob * prob;

static struct GNUNET_TIME_Absolute start;
static struct GNUNET_TIME_Absolute end;


void solve_mlp(int presolve)
{
	int result, solution;

	glp_iocp opt_mlp;
	glp_init_iocp(&opt_mlp);
	opt_mlp.msg_lev = GLP_MSG_OFF;
	opt_mlp.presolve = GLP_OFF;

	result = glp_intopt (prob, &opt_mlp);
	solution =  glp_mip_status (prob);
	GNUNET_assert ((solution == 5) && (result==0));
}

void solve_lp(int presolve)
{
	int result, solution;

	glp_smcp opt_lp;
	glp_init_smcp(&opt_lp);

	opt_lp.msg_lev = GLP_MSG_OFF;
	if (presolve==GNUNET_YES) opt_lp.presolve = GLP_ON;
	else opt_lp.presolve = GLP_OFF;

	result = glp_simplex(prob, &opt_lp);
	solution =  glp_get_status (prob);
	GNUNET_assert ((solution == 5) && (result==0));
}

/* Modify quality constraint */
void modify_qm(int start, int length, int values_to_change)
{
	//int * ind = GNUNET_malloc (length * sizeof (int));
	//double *val = GNUNET_malloc (length * sizeof (double));
	int ind[1000];
	double val[1000];

	int res = 0;
	int c = start, c2=1;
	while (c<=(start+values_to_change))
	{
		res = glp_get_mat_row(prob, c, ind, val);

		printf("%i %i \n", c, res);
		for (c2=0; c2<res; c2++)
		{
			printf("%i = %f \n", ind[c2], val[c2]);
		}

		c++;
	}
	//glp_set_mat_row(prob, start, length, ind, val);
}



void bench_simplex_optimization(char * file, int executions)
{

	int c;
	prob = glp_create_prob();
	glp_read_lp(prob, NULL, file);

	solve_lp(GNUNET_YES);

	for (c=0; c<executions;c++)
	{
		start = GNUNET_TIME_absolute_get();
		solve_lp(GNUNET_NO);
		end = GNUNET_TIME_absolute_get();

		exec_time[c] = GNUNET_TIME_absolute_get_difference(start, end).rel_value;

		sim_with_opt_avg += exec_time[c];
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Simplex /w optimization iterations %i: %llu \n",  c, exec_time[c]);
	}

	glp_delete_prob(prob);
}


void bench_simplex_no_optimization(char * file, int executions)
{

	int c;
	prob = glp_create_prob();
	glp_read_lp(prob, NULL, file);

	for (c=0; c<executions;c++)
	{
		start = GNUNET_TIME_absolute_get();
		solve_lp(GNUNET_YES);
		end = GNUNET_TIME_absolute_get();

		exec_time[c] = GNUNET_TIME_absolute_get_difference(start, end).rel_value;

		sim_no_opt_avg += exec_time[c];
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Simplex iterations %i: %llu \n",  c, exec_time[c]);
	}

	glp_delete_prob(prob);
}

void bench_mlp_no_optimization(char * file, int executions)
{

	int c;
	prob = glp_create_prob();
	glp_read_lp(prob, NULL, file);

	for (c=0; c<executions;c++)
	{
		start = GNUNET_TIME_absolute_get();
		solve_lp(GNUNET_YES);
		solve_mlp (GNUNET_NO);
		end = GNUNET_TIME_absolute_get();

		exec_time[c] = GNUNET_TIME_absolute_get_difference(start, end).rel_value;

		mlp_no_opt_avg += exec_time[c];
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MLP iterations no optimization %i: %llu \n",  c, exec_time[c]);
	}

	glp_delete_prob(prob);
}


void bench_mlp_with_optimization(char * file, int executions, int changes)
{
	int c;
	prob = glp_create_prob();
	glp_read_lp(prob, NULL, file);

	solve_lp(GNUNET_YES);

	for (c=0; c<executions;c++)
	{
		start = GNUNET_TIME_absolute_get();
		//modify_qm(906, 0, 0);
		solve_lp(GNUNET_NO);
		solve_mlp (GNUNET_NO);
		end = GNUNET_TIME_absolute_get();

		exec_time[c] = GNUNET_TIME_absolute_get_difference(start, end).rel_value;

		mlp_with_opt_avg += exec_time[c];
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "MLP /w optimization iterations %i: %llu \n",  c, exec_time[c]);
	}

	glp_delete_prob(prob);
}

#if 0
void modify_cr (int start, int length, int count)
{
	//int * ind = GNUNET_malloc (length * sizeof (int));
	//double *val = GNUNET_malloc (length * sizeof (double));
	int ind[500];
	double val[500];
	int res = 0;
	int c = start, c2=1;
	while (c<=(start+count))
	{
		res = glp_get_mat_row(prob, c, ind, val);

		printf("row index: %i non-zero elements: %i \n", c, res);
		for (c2=1; c2<=res; c2++)
		{
			printf("%i = %f ", ind[c2], val[c2]);
		}
		c++;
		printf ("\n----\n");
	}
	//glp_set_mat_row(prob, start, length, ind, val);
}
#endif
#endif

int main (int argc, char *argv[])
{
  int ret = 0;
  GNUNET_log_setup ("perf-transport-ats",
#if VERBOSE
                    "DEBUG",
#else
                    "INFO",
#endif
                    NULL);

#if !HAVE_LIBGLPK
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "GLPK not installed, exiting testcase\n");
	return 0;
#else
#if 0
#endif
  int nullfd = OPEN ("/dev/null", O_RDWR | O_APPEND);
  if (nullfd < 0)
    return GNUNET_SYSERR;
  /* set stdin/stdout to /dev/null */
  //stdi
  if (/*(dup2 (nullfd, 0) < 0) || */(dup2 (nullfd, 1) < 0))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "dup2");
    (void) CLOSE (nullfd);
    return GNUNET_SYSERR;
  }


  char * file = "ats_mlp_p100_m400.problem";

  bench_simplex_no_optimization (file, executions);
  bench_simplex_optimization (file, executions);
  bench_mlp_no_optimization (file, executions);
  bench_mlp_with_optimization (file, executions, 0);

  // -> 400 addresses
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
      "Simplex, no optimization, average per address: %f\n",
      ((double) sim_no_opt_avg / EXECS) / 400);
  GAUGER ("TRANSPORT","GLPK simplex  no optimization",
      ((double) sim_no_opt_avg  / EXECS) / 400, "ms/address");

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
      "Simplex, with optimization, average per address: %f\n",
      ((double) sim_with_opt_avg / EXECS) / 400);
  GAUGER ("TRANSPORT",
      "GLPK simplex, 100 peers 400 addresses with optimization",
      ((double) sim_with_opt_avg  / EXECS) / 400, "ms/address");

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
      "MLP no optimization average per address: %f\n",
      ((double) mlp_no_opt_avg  / EXECS) / 400);
  GAUGER ("TRANSPORT","GLPK MLP 100 peers 400 addresses no optimization",
      ((double) mlp_no_opt_avg  / EXECS) / 400, "ms/address");

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
      "MLP optimization average per address: %f\n",
      ((double) mlp_with_opt_avg/ EXECS) / 400);
  GAUGER ("TRANSPORT",
      "GLPK MLP 100 peers 400 addresses with optimization",
      ((double) mlp_with_opt_avg  / EXECS) / 400, "ms/address");

#endif
  (void) CLOSE (nullfd);
  return ret;
}

/* end of per_transport_ats.c*/

