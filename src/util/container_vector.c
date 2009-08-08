/*
      This file is part of GNUnet

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file util/container_vector.c
 * @brief Implementation of a dynamic array
 * @author Antti Salonen, Christian Grothoff
 * @version vector.c,v 1.3 2004/05/02 20:22:52 aksalone Exp
 *
 * An implementation of a dynamic array of objects. Like an array, the
 * vector's elements are indexed, but it is also possible to
 * dynamically resize the vector by inserting and removing elements at
 * any location.  The vector is implemented as a double-linked list of
 * arrays, each with a static maximum length. When one array fills up,
 * it's splitted into two half-full arrays, and so forth. With
 * functions {insert,get,remove}_last the vector can also be used as a
 * fairly efficient stack.  The functions
 * get_{at,first,last,next,previous} allow traversing the vector in an
 * efficient manner, each function call taking more or less constant
 * time. Vector_get_next and Vector_get_first may only be called after
 * a call to one of vector_get_{first,last,at}, which set the vector's
 * iterator. All functions that modify the vector's contents unset the
 * iterator.
 */

#include "platform.h"
#include "gnunet_common.h"

typedef struct GNUNET_CONTAINER_Vector {
  unsigned int VECTOR_SEGMENT_SIZE;
  struct vector_segment_t * segmentsHead;
  struct vector_segment_t * segmentsTail;
  struct vector_segment_t * iteratorSegment;
  unsigned int iteratorIndex;
  size_t size;
} GNUNET_CONTAINER_Vector;


typedef struct vector_segment_t {
  void ** data; /* always of size VECTOR_SEGMENT_SIZE */
  struct vector_segment_t *next;
  struct vector_segment_t *previous;
  size_t size;
} VectorSegment;

/**
 * A debug function that traverses the linked list and prints the
 * sizes of the segments. This currently isn't used.
 */
void GNUNET_CONTAINER_vector_dump(struct GNUNET_CONTAINER_Vector *v) {
  VectorSegment *vs;
  int n;
  unsigned int sum = 0;

  for (vs = v->segmentsHead; vs; vs = vs->next) {
    fprintf(stderr,
	    "Segment-size: %3llu / %llu [%llu...%llu]: ",
	    (unsigned long long) vs->size,
	    (unsigned long long) v->VECTOR_SEGMENT_SIZE,
	    (unsigned long long) sum,
	    (unsigned long long) (sum + vs->size - 1));
    for (n=0;n<vs->size;n++) {
      fprintf(stderr,
	      "%p, ",
	      vs->data[n]);
    }
    fprintf(stderr, "\n");
    sum += vs->size;
  }
  fprintf(stderr,
	  "Vector size: %u\n",
	  sum);
}

/**
 * Remove and return the element at given index in the segment's array. The
 * trailing pointers in the array, if any, are moved backwards to fill the gap.
 */
static void *vectorSegmentRemoveAtIndex(VectorSegment *vs,
					int index) {
   void *rvalue = vs->data[index];

   while (index < vs->size) {
      vs->data[index] = vs->data[index + 1];
      index++;
   }
   return rvalue;
}


/**
 * Split the full segment vs into two half-full segments.
 */
static void vectorSegmentSplit(struct GNUNET_CONTAINER_Vector *v,
			       VectorSegment *vs) {
   VectorSegment *oldNext;
   int moveCount;

   oldNext = vs->next;
   vs->next = GNUNET_malloc(sizeof(VectorSegment));
   vs->next->data = GNUNET_malloc(v->VECTOR_SEGMENT_SIZE * sizeof(void*));
   vs->next->previous = vs;
   vs->next->next = oldNext;
   if (NULL != oldNext)
     oldNext->previous = vs->next;
   else
      v->segmentsTail = vs->next;
   moveCount = vs->size / 2;
   memcpy(vs->next->data,
	  vs->data + (vs->size - moveCount),
	  moveCount * sizeof (void *));
   vs->next->size = moveCount;
   vs->size -= moveCount;
}

/**
 * Joins the given segment with the following segment. The first segment _must_
 * be empty enough to store the data of both segments.
 */
static void vectorSegmentJoin(struct GNUNET_CONTAINER_Vector *v,
			      VectorSegment *vs) {
  VectorSegment *oldNext = vs->next->next;

  memcpy(vs->data + vs->size,
	 vs->next->data,
	 vs->next->size * sizeof (void *));
  vs->size += vs->next->size;
  GNUNET_free(vs->next->data);
  GNUNET_free(vs->next);
  vs->next = oldNext;
  if (oldNext != NULL)
    vs->next->previous = vs;
  else
    v->segmentsTail = vs;
}

/**
 * Free an empty segment, _unless_ it is the only segment.
 */
static void vectorSegmentRemove(struct GNUNET_CONTAINER_Vector *v,
				VectorSegment *vs) {
  if ( (vs->previous == NULL) &&
       (vs->next == NULL) )
    return;
  if (vs->previous != NULL)
    vs->previous->next = vs->next;
  else
    v->segmentsHead = vs->next;
  if (vs->next != NULL)
    vs->next->previous = vs->previous;
  else
    v->segmentsTail = vs->previous;
  GNUNET_free(vs->data);
  GNUNET_free(vs);
}


/**
 * Search for given index in the vector v. When the index is found, its
 * segment and relative index are written to parameters vs and segment_index.
 * If possible, an unused index at the end of a segment is returned, as this
 * is also a requirement for adding data in an empty vector.
 */
static int vectorFindNewIndex(struct GNUNET_CONTAINER_Vector * v,
			      unsigned int index,
			      VectorSegment **vs) {
  VectorSegment *segment;
  int segmentStartIndex;

  if (index > v->size) {
    *vs = NULL;
    return -1;
  }
  if (index <= v->size / 2) { /* empty vector included */
    segment = v->segmentsHead;
    segmentStartIndex = 0;
    while (index > segmentStartIndex + segment->size) {
      segmentStartIndex += segment->size;
      segment = segment->next;
    }
  } else { /* reverse */
    segment = v->segmentsTail;
    segmentStartIndex = v->size - segment->size;
    while (index <= segmentStartIndex) {
      segment = segment->previous;
      segmentStartIndex -= segment->size;
    }
  }
  *vs = segment;
  return index - segmentStartIndex;
}


/**
 * Find the segment and segmentIndex of the element
 * with the given index.
 */
static int vectorFindIndex(struct GNUNET_CONTAINER_Vector *v,
			   unsigned int index,
			   VectorSegment **vs) {
  VectorSegment *segment;
  int segmentStartIndex;

  if (index >= v->size) {
    *vs = NULL;
    return -1;
  }
  if (index < v->size / 2) {
    segment = v->segmentsHead;
    segmentStartIndex = 0;
    while (index >= segmentStartIndex + segment->size) {
      segmentStartIndex += segment->size;
      segment = segment->next;
    }
  } else {
    segment = v->segmentsTail;
    segmentStartIndex = v->size - segment->size;
    while (index < segmentStartIndex) {
      segment = segment->previous;
      segmentStartIndex -= segment->size;
    }
  }
  *vs = segment;
  return index - segmentStartIndex;
}


/*
 * Traverse the vector looking for a given object. When found, set the pointer
 * pointed to by vs to point to the object's segment and the integer pointed
 * to by segmentIndex to the object's index in the segment. If the object is
 * not found, *vs is set to NULL.
 */
static void vectorFindObject(struct GNUNET_CONTAINER_Vector *v,
			     void *object,
			     VectorSegment **vs,
			     int *segmentIndex) {
  VectorSegment *segment;
  int i;

  segment = v->segmentsHead;
  while (NULL != segment) {
    for (i=0;i<segment->size;i++) {
      if (segment->data[i] == object) {
	*vs = segment;
	*segmentIndex = i;
	return;
      }
    }
    segment = segment->next;
  }
  *vs = NULL;
}


/**
 * Allocate a new vector structure with a single empty data segment.
 */
struct GNUNET_CONTAINER_Vector * GNUNET_CONTAINER_vector_create(unsigned int vss) {
   struct GNUNET_CONTAINER_Vector *rvalue;

   if (vss < 2)
     return NULL; /* invalid! */
   rvalue = GNUNET_malloc(sizeof (GNUNET_CONTAINER_Vector));
   rvalue->VECTOR_SEGMENT_SIZE = vss;
   rvalue->size = 0;
   rvalue->segmentsHead = GNUNET_malloc(sizeof(VectorSegment));
   rvalue->segmentsHead->data = GNUNET_malloc(sizeof(void*)*vss);
   rvalue->segmentsTail = rvalue->segmentsHead;
   rvalue->segmentsHead->next = NULL;
   rvalue->segmentsHead->previous = NULL;
   rvalue->segmentsHead->size = 0;
   rvalue->iteratorSegment = NULL;
   rvalue->iteratorIndex = 0;
   return rvalue;
}

/**
 * Free vector structure including its data segments, but _not_ including the
 * stored void pointers. It is the user's responsibility to empty the vector
 * when necessary to avoid memory leakage.
 */
void GNUNET_CONTAINER_vector_destroy(struct GNUNET_CONTAINER_Vector *v) {
  VectorSegment * vs;
  VectorSegment * vsNext;

  vs = v->segmentsHead;
  while (vs != NULL) {
    vsNext = vs->next;
    GNUNET_free(vs->data);
    GNUNET_free(vs);
    vs = vsNext;
  }
  GNUNET_free(v);
}

/**
 * Return the size of the vector.
 */
size_t GNUNET_CONTAINER_vector_size(struct GNUNET_CONTAINER_Vector *v) {
   return v->size;
}

/**
 * Insert a new element in the vector at given index. The return value is
 * GNUNET_OK on success, GNUNET_SYSERR if the index is out of bounds.
 */
int GNUNET_CONTAINER_vector_insert_at(struct GNUNET_CONTAINER_Vector *v,
		   void *object,
		   unsigned int index) {
  VectorSegment *segment;
  int segmentIndex;
  int i;

  if (index > v->size)
    return GNUNET_SYSERR;
  v->iteratorSegment = NULL;
  segmentIndex = vectorFindNewIndex(v, index, &segment);
  if (segmentIndex == -1)
    return GNUNET_SYSERR;
  for (i = segment->size; i > segmentIndex; i--)
    segment->data[i] = segment->data[i - 1];
  segment->data[segmentIndex] = object;
  v->size++;
  segment->size++;
  if (segment->size == v->VECTOR_SEGMENT_SIZE)
    vectorSegmentSplit(v, segment);
  return GNUNET_OK;
}

/**
 * Insert a new element at the end of the vector.
 */
void GNUNET_CONTAINER_vector_insert_last(struct GNUNET_CONTAINER_Vector *v, void *object) {
  v->iteratorSegment = NULL;
  v->segmentsTail->data[v->segmentsTail->size++] = object;
  if (v->segmentsTail->size == v->VECTOR_SEGMENT_SIZE)
    vectorSegmentSplit(v, v->segmentsTail);
  v->size++;
}

/**
 * Return the element at given index in the vector or NULL if the index is out
 * of bounds. The iterator is set to point to the returned element.
 */
void * GNUNET_CONTAINER_vector_get_at(struct GNUNET_CONTAINER_Vector *v,
		   unsigned int index) {
  int ret;
  if ( (index < 0) || (index >= v->size) )
    return NULL;
  ret = vectorFindIndex(v,
			index,
			&v->iteratorSegment);
  if (ret == -1)
    return NULL;
  v->iteratorIndex = ret;
  return v->iteratorSegment->data[ret];
}

/**
 * Return the first element in the vector, whose index is 0, or NULL if the
 * vector is empty. The iterator of the vector is set to point to the first
 * element.
 */
void * GNUNET_CONTAINER_vector_get_first(struct GNUNET_CONTAINER_Vector *v) {
  if (v->size == 0)
    return NULL;
  v->iteratorSegment = v->segmentsHead;
  v->iteratorIndex = 0;
  return v->iteratorSegment->data[0];
}

/**
 * Return the last element in the vector or NULL if the vector is
 * empty. The iterator of the vector is set to the last element.
 */
void * GNUNET_CONTAINER_vector_get_last(struct GNUNET_CONTAINER_Vector *v) {
  if (v->size == 0)
    return NULL;
  v->iteratorSegment = v->segmentsTail;
  v->iteratorIndex = v->segmentsTail->size-1;
  return v->segmentsTail->data[v->iteratorIndex];
}

/**
 * Return the next element in the vector, as called after vector_get_at() or
 * vector_get_first(). The return value is NULL if there are no more elements
 * in the vector or if the iterator has not been set.
 */
void * GNUNET_CONTAINER_vector_get_next(struct GNUNET_CONTAINER_Vector *v) {
  if (v->iteratorSegment == NULL)
    return NULL;
  if (++v->iteratorIndex >= v->iteratorSegment->size) {
    if (v->iteratorSegment == v->segmentsTail) {
      v->iteratorSegment = NULL;
      return NULL;
    } else {
      v->iteratorSegment = v->iteratorSegment->next;
      v->iteratorIndex = 0;
    }
  }
  return v->iteratorSegment->data[v->iteratorIndex];
}

/**
 * Return the previous element in the vector, as called after vector_get_at()
 * or vector_get_last(). The return value is NULL if there are no more
 * elements in the vector or if the iterator has not been set.
 */
void * GNUNET_CONTAINER_vector_get_previous(struct GNUNET_CONTAINER_Vector * v) {
  if (v->iteratorSegment == NULL)
    return NULL;
  if (--v->iteratorIndex == -1) {
    if (v->iteratorSegment == v->segmentsHead) {
      v->iteratorSegment = 0;
      return NULL;
    } else {
      v->iteratorSegment = v->iteratorSegment->previous;
      v->iteratorIndex = v->iteratorSegment->size - 1;
    }
  }
  return v->iteratorSegment->data[v->iteratorIndex];
}

/**
 * Delete and return the element at given index. NULL is returned if index is
 * out of bounds.
 */
void * GNUNET_CONTAINER_vector_remove_at(struct GNUNET_CONTAINER_Vector *v,
		      unsigned int index) {
  VectorSegment * segment;
  int segmentIndex;
  void *rvalue;

  if (index >= v->size)
     return NULL;
  v->iteratorSegment = NULL;
  segmentIndex = vectorFindIndex(v, index, &segment);
  if (segmentIndex == -1)
    return NULL;
  rvalue = vectorSegmentRemoveAtIndex(segment,
				      segmentIndex);
  /* If the segment ends empty remove it, otherwise
     try to join it with its neighbors. */
  if (--segment->size == 0)
    vectorSegmentRemove(v, segment);
  else if (segment->next &&
	   segment->size + segment->next->size < v->VECTOR_SEGMENT_SIZE)
    vectorSegmentJoin(v, segment);
  else if (segment->previous &&
	   segment->size + segment->previous->size < v->VECTOR_SEGMENT_SIZE)
    vectorSegmentJoin(v, segment->previous);
  v->size--;
  return rvalue;
}

/**
 * Delete and return the last element in the vector, or NULL if the vector
 * is empty.
 */
void *GNUNET_CONTAINER_vector_remove_last (struct GNUNET_CONTAINER_Vector *v) {
  void *rvalue;

  if (v->size == 0)
    return NULL;
  v->iteratorSegment = NULL;
  rvalue = v->segmentsTail->data[v->segmentsTail->size - 1];
  /* If the segment ends empty remove it, otherwise join it if necessary. */
  if (--v->segmentsTail->size == 0)
    vectorSegmentRemove(v, v->segmentsTail);
  else if ( (v->segmentsTail->previous != NULL) &&
	    (v->segmentsTail->size + v->segmentsTail->previous->size
	     < v->VECTOR_SEGMENT_SIZE) )
    vectorSegmentJoin (v, v->segmentsTail->previous);
  v->size--;
  return rvalue;
}

/**
 * Delete and return given object from the vector, or return NULL if the object
 * is not found.
 */
void * GNUNET_CONTAINER_vector_remove_object(struct GNUNET_CONTAINER_Vector *v, void *object) {
  VectorSegment *segment;
  int segmentIndex;
  void * rvalue;

  v->iteratorSegment = NULL;
  vectorFindObject(v, object, &segment, &segmentIndex);
  if (segment == NULL)
    return NULL;
  rvalue = vectorSegmentRemoveAtIndex(segment, segmentIndex);
  /* If the segment ends empty remove it, otherwise join it if necessary. */
  if (--segment->size == 0)
    vectorSegmentRemove (v, segment);
  else if ( (segment->next != NULL) &&
	    (segment->size + segment->next->size < v->VECTOR_SEGMENT_SIZE) )
    vectorSegmentJoin (v, segment);
  else if ( (segment->previous != NULL) &&
	    (segment->size + segment->previous->size < v->VECTOR_SEGMENT_SIZE) )
    vectorSegmentJoin (v, segment->previous);
  v->size--;
  return rvalue;
}

/**
 * Set the given index in the vector. The old value of the index is
 * returned, or NULL if the index is out of bounds.
 */
void *GNUNET_CONTAINER_vector_set_at (struct GNUNET_CONTAINER_Vector *v,
		   void *object,
		   unsigned int index) {
  VectorSegment *segment;
  int segmentIndex;
  void *rvalue;

  if (index >= v->size)
    return NULL;
  v->iteratorSegment = NULL;
  segmentIndex = vectorFindIndex(v, index, &segment);
  if (segmentIndex == -1)
    return NULL;
  rvalue = segment->data[segmentIndex];
  segment->data[segmentIndex] = object;
  return rvalue;
}


/**
 * Set the index occupied by the given object to point to the new object.
 * The old object is returned, or NULL if it's not found.
 */
void *GNUNET_CONTAINER_vector_set_object(struct GNUNET_CONTAINER_Vector *v,
		      void *object,
		      void *oldObject) {
  VectorSegment *segment;
  int segmentIndex;
  void *rvalue;

  v->iteratorSegment = NULL;
  vectorFindObject (v, oldObject, &segment, &segmentIndex);
  if (segment == NULL)
    return NULL;
  rvalue = segment->data[segmentIndex];
  segment->data[segmentIndex] = object;
  return rvalue;
}


/**
 * Swaps the contents of index1 and index2. Return value is GNUNET_OK
 * on success, GNUNET_SYSERR if either index is out of bounds.
 */
int GNUNET_CONTAINER_vector_swap(struct GNUNET_CONTAINER_Vector *v,
	       unsigned int index1,
	       unsigned int index2) {
  VectorSegment * segment1;
  VectorSegment * segment2;
  int segmentIndex1;
  int segmentIndex2;
  void *temp;

  if ( (index1 >= v->size) ||
       (index2 >= v->size) )
    return GNUNET_SYSERR;
  v->iteratorSegment= NULL;
  segmentIndex1 = vectorFindIndex(v, index1, &segment1);
  segmentIndex2 = vectorFindIndex(v, index2, &segment2);
  if( (segmentIndex1 == -1) ||
      (segmentIndex2 == -1) )
    return GNUNET_SYSERR;
  temp = segment1->data[segmentIndex1];
  segment1->data[segmentIndex1] = segment2->data[segmentIndex2];
  segment2->data[segmentIndex2] = temp;
  return GNUNET_OK;
}

/**
 * Return the index of given element or -1 if the element is not found.
 */
unsigned int GNUNET_CONTAINER_vector_index_of(struct GNUNET_CONTAINER_Vector *v,
			   void *object) {
  VectorSegment * segment;
  unsigned int i;
  unsigned int segmentStartIndex;

  segmentStartIndex = 0;
  segment = v->segmentsHead;
  while (NULL != segment) {
    for (i = 0; i < segment->size; i++)
      if (segment->data[i] == object)
	return segmentStartIndex + i;
    segmentStartIndex += segment->size;
    segment = segment->next;
  }
  return (unsigned int) -1;
}


/*
 * Return the data stored in the vector as a single dynamically allocated
 * array of (void *), which must be free(3)d by the user. Use the functions
 * get_{at,first,last,next,previous} instead, unless you really need to access
 * everything in the vector as fast as possible.
 */
void ** GNUNET_CONTAINER_vector_elements (struct GNUNET_CONTAINER_Vector *v) {
  void **rvalue;
  VectorSegment *vs;
  size_t i = 0;

  rvalue = GNUNET_malloc_large(v->size * sizeof (void *));
  for (vs = v->segmentsHead; vs; vs = vs->next) {
    memcpy (rvalue + i,
	    vs->data,
	    vs->size * sizeof (void *));
    i += vs->size;
  }
  return rvalue;
}



/* end of vector.c */
