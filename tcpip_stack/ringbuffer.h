#pragma once
typedef struct {
	unsigned char *buffer;	/* the buffer holding the data */
	unsigned int size;	/* the size of the allocated buffer */
	unsigned int in;	/* data is added at offset (in % size) */
	unsigned int out;	/* data is extracted from off. (out % size) */
}ringbuffer_t;
void ringbuffer_init(ringbuffer_t *fifo, void *buffer,
	unsigned int size);
unsigned int ringbuffer_put(ringbuffer_t *fifo,
	const void *from, unsigned int len);
unsigned int ringbuffer_out(ringbuffer_t *fifo,
	void *to, unsigned int len);
unsigned int ringbuffer_peek(ringbuffer_t *fifo,
	void *to, unsigned int len, unsigned offset);
