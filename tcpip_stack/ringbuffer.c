#include "ringbuffer.h"
#define min(a,b)a < b ? a : b




static inline unsigned int ringbuffer_len(ringbuffer_t *fifo)
{
	register unsigned int	out;
	out = fifo->out;
	return fifo->in - out;
}

/**
* kfifo_avail - returns the number of bytes available in the FIFO
* @fifo: the fifo to be used.
*/
static inline  unsigned int ringbuffer_avail(ringbuffer_t *fifo)
{
	return fifo->size - ringbuffer_len(fifo);
}

static inline unsigned int __ringbuffer_off(ringbuffer_t *fifo, unsigned int off)
{
	return off & (fifo->size - 1);
}


void ringbuffer_init(ringbuffer_t *fifo, void *buffer,
	unsigned int size)
{
	//size must is power of 2
	fifo->buffer = (unsigned char*)buffer;
	fifo->size = size;

	fifo->in = fifo->out = 0;
}
static inline void __ringbuffer_in_data(ringbuffer_t *fifo,
	const void *from, unsigned int len, unsigned int off)
{
	unsigned int l;

	/*
	* Ensure that we sample the fifo->out index -before- we
	* start putting bytes into the kfifo.
	*/


	off = __ringbuffer_off(fifo, fifo->in + off);

	/* first put the data starting from fifo->in to buffer end */
	l = min(len, fifo->size - off);
	memcpy(fifo->buffer + off, from, l);

	/* then put the rest (if any) at the beginning of the buffer */
	memcpy(fifo->buffer, (unsigned char*)from + l, len - l);
}

static inline void __ringbuffer_add_in(ringbuffer_t *fifo,
	unsigned int off)
{
	fifo->in += off;
}


unsigned int ringbuffer_put(ringbuffer_t *fifo, const void *from,
	unsigned int len)
{
	len = min(ringbuffer_avail(fifo), len);

	__ringbuffer_in_data(fifo, from, len, 0);
	__ringbuffer_add_in(fifo, len);
	return len;
}

static inline void __ringbuffer_out_data(ringbuffer_t *fifo,
	void *to, unsigned int len, unsigned int off)
{
	unsigned int l;

	/*
	* Ensure that we sample the fifo->in index -before- we
	* start removing bytes from the kfifo.
	*/


	off = __ringbuffer_off(fifo, fifo->out + off);

	/* first get the data from fifo->out until the end of the buffer */
	l = min(len, fifo->size - off);
	memcpy(to, fifo->buffer + off, l);

	/* then get the rest (if any) from the beginning of the buffer */
	memcpy((unsigned char*)to + l, fifo->buffer, len - l);
}


static inline void __ringbuffer_add_out(ringbuffer_t *fifo,
	unsigned int off)
{
	fifo->out += off;
}

unsigned int __ringbuffer_out_n(ringbuffer_t *fifo,
	void *to, unsigned int len, unsigned int recsize)
{
	if (ringbuffer_len(fifo) < len + recsize)
		return len;

	__ringbuffer_out_data(fifo, to, len, recsize);
	__ringbuffer_add_out(fifo, len + recsize);
	return 0;
}


unsigned int ringbuffer_out(ringbuffer_t *fifo, void *to, unsigned int len)
{
	len = min(ringbuffer_len(fifo), len);

	__ringbuffer_out_data(fifo, to, len, 0);
	__ringbuffer_add_out(fifo, len);

	return len;
}


unsigned int ringbuffer_peek(ringbuffer_t *fifo, void *to, unsigned int len,
	unsigned offset)
{
	len = min(ringbuffer_len(fifo) - offset, len);

	__ringbuffer_out_data(fifo, to, len, offset);
	return len;
}
