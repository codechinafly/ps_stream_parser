#pragma once
#include <cstdint> // for uint8_t
#include <cstddef> // for std::size_t
#ifdef _MSC_VER 
#include <WinSock2.h> // for windows ntohs
#else
#include <netinet/in.h> // for linux ntohs
#endif

#define CHECK_PS_BUF_OVERFLOW(current_size, append_size, max_size, start_code_found) \
if (current_size + append_size > max_size) { current_size = 0; start_code_found = false; return; }

class ps_stream_parser
{
public:
	class callback
	{
	public:
		virtual void on_ps_pack_parse_begin() = 0;
		virtual void on_ps_pack_pes_es_data(const uint8_t* es, std::size_t es_size, uint8_t stream_type) = 0;
		virtual void on_ps_pack_parse_end() = 0;
	};

	ps_stream_parser(callback* cb, std::size_t max_ps_size = 200 * 1024)
	{
		cb_ = cb;
		max_ps_size_ = max_ps_size;
		start_code_found_ = false;
		ps_buf_ = (uint8_t*)malloc(max_ps_size);
		ps_size_ = 0;
		memset(stream_types_, 0, sizeof(stream_types_));
	}

	~ps_stream_parser()
	{
		if (ps_buf_)
		{
			free(ps_buf_);
			ps_buf_ = nullptr;
		}
	}

	void put_stream(const uint8_t* stream, std::size_t size)
	{
		if (start_code_found_)
		{
			CHECK_PS_BUF_OVERFLOW(ps_size_, size, max_ps_size_, start_code_found_);
			memcpy(ps_buf_ + ps_size_, stream, size);
			ps_size_ += size;
		}
		else if (stream[0] == 0x00 && stream[1] == 0x00 && stream[2] == 0x01 && stream[3] == 0xba)
		{
			if (start_code_found_)
			{
				__ps_parse(ps_buf_, ps_size_);
				ps_size_ = 0;
				CHECK_PS_BUF_OVERFLOW(ps_size_, size, max_ps_size_, start_code_found_);
				memcpy(ps_buf_ + ps_size_, stream, size);
				ps_size_ += size;
			}
			else
			{
				CHECK_PS_BUF_OVERFLOW(ps_size_, size, max_ps_size_, start_code_found_);
				start_code_found_ = true;
				memcpy(ps_buf_ + ps_size_, stream, size);
				ps_size_ += size;
			}
		}
	}

private:
	void __ps_parse(const uint8_t* data, std::size_t size)
	{
		cb_->on_ps_pack_parse_begin();
		const uint8_t* p = data;
		const uint8_t* ep = data + size;
		std::size_t stuffing_len = p[13] & 0x7;
		// skip ps pack header and stuffing length
		p += 4 + 10 + stuffing_len;
		while (p < ep)
		{
			// check start code prefix
			if (p[0] != 0x00 || p[1] != 0x00 || p[2] != 0x01) break;
			uint8_t stream_id = *(p + 3);
			if (stream_id == 0xbb) // system header
			{
				// only skip system header
				p += 4;  /* skip start code */
				std::size_t header_length = ntohs(*((uint16_t*)p));
				p += (header_length + 2); /* skip header lenght and 2byte */
			}
			else if (stream_id == 0xbc) // map stream
			{
				{
					// get stream types
					const uint8_t* pp = p;
					pp += 4; // skip start code and stream id
					pp += 4; // skip next 4 byte
					std::size_t program_stream_info_length = ntohs(*((uint16_t*)pp));
					pp += (2 + program_stream_info_length);
					std::size_t elementary_stream_map_length = ntohs(*((uint16_t*)pp));
					pp += 2;
					std::size_t count = elementary_stream_map_length / 4;
					for (std::size_t i = 0; i < count; ++i)
					{
						stream_types_[*(pp + 1)] = (*pp);
						pp += 4;
					}
				}
				// skip map stream
				p += 4;  /* skip start code */
				std::size_t header_length = ntohs(*((uint16_t*)p));
				p += (header_length + 2);
			}
			else if ((stream_id >= 0xe0 && stream_id <= 0xef) || // video
				(stream_id >= 0xc0 && stream_id <= 0xdf)) // audio
			{
				const uint8_t* es = nullptr;
				std::size_t es_size = 0;
				p = __pes_parse(p, &es, &es_size);
				if (p > ep) break; // check pointer overflow
				cb_->on_ps_pack_pes_es_data(es, es_size, stream_types_[stream_id]);
			}
			else
			{
				p += 4;  /* skip start code */
				std::size_t header_length = ntohs(*((uint16_t*)p));
				p += (header_length + 2); /* only skip */
			}
		}
		cb_->on_ps_pack_parse_end();
	}

	const uint8_t* __pes_parse(const uint8_t* p, const uint8_t** es_ptr, std::size_t* es_size)
	{
		p += 4; /* skip start code */
		std::size_t pes_pck_len = ntohs(*((uint16_t*)p));
		p += 4;
		std::size_t pes_header_data_len = *p;
		p += (pes_header_data_len + 1);
		*es_ptr = p;
		*es_size = pes_pck_len - 2 - 1 - pes_header_data_len;
		p += *es_size;
		return p;
	}

private:
	callback* cb_;
	std::size_t max_ps_size_;
	bool start_code_found_;
	uint8_t* ps_buf_;
	std::size_t ps_size_;
	uint8_t stream_types_[0xff];
};
