/* This file is in the public domain. */

/**
 * @brief Program to simulate results from #GCP_get_desirability_of_path()
 * for various plausible inputs.
 * @author Christian Grothoff
 */
#include <stdio.h>

int
main ()
{
  for (unsigned int num_alts=1; num_alts<10; num_alts++)
    for (unsigned int off=0; off<10; off++)
      for (double delta=-(int) off;delta<=5;delta += 0.25)
      {
        double weight_alts;

        if (delta <= - 1.0)
          weight_alts = - 1.0 * num_alts / delta; /* discount alternative paths */
        else if (delta >= 1.0)
          weight_alts = 1.0 * num_alts * delta; /* overcount alternative paths */
        else
          weight_alts = 1.0 * num_alts; /* count alternative paths normally */

        fprintf (stderr,
                 "Paths: %u  Offset: %u  Delta: %5.2f  SCORE: %f\n",
                 num_alts,
                 off,
                 delta,
                 ((off + 1.0) / (weight_alts * weight_alts)));
      }


}
