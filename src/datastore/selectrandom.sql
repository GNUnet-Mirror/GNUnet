select *
from (select random() as v from (values(1))) t1,
     (select max(repl) as m from data) t2,
     (select * from data
      where repl=t2.m and
            rnd>=t.v
      order by rnd
      limit 1)

