#include "OSNReceiver.h"
#include "libOTe/Base/BaseOT.h"
#include "cryptoTools/Common/BitVector.h"
#include <cryptoTools/Crypto/AES.h>
#include <libOTe/TwoChooseOne/SilentOtExtSender.h>
#include <libOTe/TwoChooseOne/IknpOtExtSender.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace std;
using namespace oc;

namespace {
uint64_t block_word(const block& value)
{
	uint64_t word = 0;
	memcpy(&word, &value, sizeof(word));
	return word;
}

block word_block(uint64_t value)
{
	return toBlock(0ULL, static_cast<u64>(value));
}

uint64_t sub_mod(uint64_t a, uint64_t b, uint64_t modulus)
{
	a %= modulus;
	b %= modulus;
	return a >= b ? a - b : modulus - (b - a);
}

void prepare_switch_shares(
	const block& m0, const block& m1,
	const std::array<block, 2>& raw0, const std::array<block, 2>& raw1,
	uint64_t modulus, block& w0, block& w1,
	std::array<block, 2>& correction, std::array<block, 2>& corrected_one)
{
	if (modulus == 0) {
		w0 = raw0[0] ^ m0;
		w1 = raw0[1] ^ m1;
		corrected_one = {m0 ^ w1, m1 ^ w0};
		correction = {raw1[0] ^ corrected_one[0], raw1[1] ^ corrected_one[1]};
		return;
	}
	const uint64_t m0v = block_word(m0) % modulus;
	const uint64_t m1v = block_word(m1) % modulus;
	const uint64_t w0v = sub_mod(m0v, block_word(raw0[0]), modulus);
	const uint64_t w1v = sub_mod(m1v, block_word(raw0[1]), modulus);
	const uint64_t desired0 = sub_mod(m0v, w1v, modulus);
	const uint64_t desired1 = sub_mod(m1v, w0v, modulus);
	w0 = word_block(w0v);
	w1 = word_block(w1v);
	corrected_one = {word_block(desired0), word_block(desired1)};
	correction = {
		word_block(sub_mod(desired0, block_word(raw1[0]), modulus)),
		word_block(sub_mod(desired1, block_word(raw1[1]), modulus))};
}
}
void OSNReceiver::rand_ot_send(std::vector<std::array<osuCrypto::block, 2>>& sendMsg, std::vector<oc::Channel>& chls)
{
	//std::cout << "\n OT sender!! \n";
	size_t num_threads = chls.size();

	size_t total_len = sendMsg.size();
	auto routine = [&](size_t tid)
	{
		size_t start_idx = total_len * tid / num_threads;
		size_t end_idx = total_len * (tid + 1) / num_threads;
		end_idx = ((end_idx <= total_len) ? end_idx : total_len);
		size_t size = end_idx - start_idx;

		osuCrypto::PRNG prng1(osuCrypto::sysRandomSeed());

		std::vector<osuCrypto::block> baseRecv(128);
		osuCrypto::DefaultBaseOT baseOTs;
		osuCrypto::BitVector baseChoice(128);
		baseChoice.randomize(prng1);
		osuCrypto::IknpOtExtSender sender;
		baseOTs.receive(baseChoice, baseRecv, prng1, chls[tid], 1);
		sender.setBaseOts(baseRecv, baseChoice);

		std::vector<std::array<osuCrypto::block, 2>> tmpMsg(size);
		sender.send(tmpMsg, prng1, chls[tid]);
		std::copy_n(tmpMsg.begin(), size, sendMsg.begin() + start_idx);
	};
	vector<thread> thrds(num_threads);
	for (size_t t = 0; t < num_threads; t++)
		thrds[t] = std::thread(routine, t);
	for (size_t t = 0; t < num_threads; t++)
		thrds[t].join();

	/*osuCrypto::PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));

	std::vector<osuCrypto::block> baseRecv(128);
	osuCrypto::DefaultBaseOT baseOTs;
	osuCrypto::BitVector baseChoice(128);
	baseChoice.randomize(prng1);
	osuCrypto::IknpOtExtSender sender;
	baseOTs.receive(baseChoice, baseRecv, prng1, chls[0], num_threads);
	sender.setBaseOts(baseRecv, baseChoice);
	sender.send(sendMsg, prng1, chls[0]);*/
}

void OSNReceiver::silent_ot_send(std::vector<std::array<osuCrypto::block, 2>>& sendMsg, std::vector<oc::Channel>& chls)
{
	//std::cout << "\n Silent OT sender!! \n";

	size_t num_threads = chls.size();
	size_t total_len = sendMsg.size();
	auto routine = [&](size_t tid)
	{
		size_t start_idx = total_len * tid / num_threads;
		size_t end_idx = total_len * (tid + 1) / num_threads;
		end_idx = ((end_idx <= total_len) ? end_idx : total_len);
		size_t size = end_idx - start_idx;

		osuCrypto::PRNG prng1(osuCrypto::sysRandomSeed());
		osuCrypto::u64 numOTs = size;

		osuCrypto::SilentOtExtSender sender;
		sender.configure(numOTs);
		std::vector<std::array<osuCrypto::block, 2>> tmpMsg(size);
		sender.silentSend(tmpMsg, prng1, chls[tid]);
		std::copy_n(tmpMsg.begin(), size, sendMsg.begin() + start_idx);
	};

	vector<thread> thrds(num_threads);
	for (size_t t = 0; t < num_threads; t++)
		thrds[t] = std::thread(routine, t);
	for (size_t t = 0; t < num_threads; t++)
		thrds[t].join();

	/*osuCrypto::PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));
	osuCrypto::u64 numOTs = sendMsg.size();

	osuCrypto::SilentOtExtSender sender;
	sender.configure(numOTs, 2, num_threads);
	sender.silentSend(sendMsg, prng1, chls[0]);*/
}

std::vector<std::vector<block>> OSNReceiver::gen_benes_client_osn(int values, std::vector<oc::Channel>& chls,
	uint64_t modulus)
{
	int N = int(ceil(log2(values)));

	int levels = 2 * N - 1;
	int switches = levels * (values / 2);
	block temp;
	std::vector<block> masks(values);
	std::vector<std::vector<block>> ret_masks(values);

	osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());

	for (int j = 0; j < values; j++)
	{ // we sample the input masks randomly
		temp = prng.get<block>();
		if (modulus != 0) temp = word_block(block_word(temp) % modulus);
		masks[j] = temp;
		ret_masks[j].push_back(temp);
	}

	std::vector<std::array<std::array<osuCrypto::block, 2>, 2>> ot_messages(switches);
	Channel& chl = chls[0];
	if (ot_type == 0)
	{
		std::vector<std::array<osuCrypto::block, 2>> tmp_messages(switches);
		osuCrypto::BitVector bit_correction(switches);
		silent_ot_send(tmp_messages, chls); // sample random ot blocks

		chl.recv(bit_correction);
		osuCrypto::block tmp;
		for (int k = 0; k < tmp_messages.size(); k++)
		{
			if (bit_correction[k] == 1)
			{
				tmp = tmp_messages[k][0];
				tmp_messages[k][0] = tmp_messages[k][1];
				tmp_messages[k][1] = tmp;
			}
		}

		AES aes(ZeroBlock);

		for (auto i = 0; i < ot_messages.size(); i++)
		{
			ot_messages[i][0] = { tmp_messages[i][0], aes.ecbEncBlock(tmp_messages[i][0]) };
			ot_messages[i][1] = { tmp_messages[i][1], aes.ecbEncBlock(tmp_messages[i][1]) };
		}
	}
	else
	{
		std::vector<std::array<osuCrypto::block, 2>> tmp_messages(switches);
		rand_ot_send(tmp_messages, chls); // sample random ot blocks
		AES aes(ZeroBlock);
		for (auto i = 0; i < ot_messages.size(); i++)
		{
			ot_messages[i][0] = { tmp_messages[i][0], aes.ecbEncBlock(tmp_messages[i][0]) };
			ot_messages[i][1] = { tmp_messages[i][1], aes.ecbEncBlock(tmp_messages[i][1]) };
		}
	}

	cpus.store(chls.size());
	std::vector<std::array<osuCrypto::block, 2>> correction_blocks(switches);
	prepare_correction(N, values, 0, 0, masks, ot_messages, correction_blocks, modulus);
	chl.send(correction_blocks);
	for (int i = 0; i < values; ++i)
	{
		ret_masks[i].push_back(masks[i]);
	}
	return ret_masks;
}

OSNReceiver::OSNReceiver(size_t size, int ot_type) : size(size), ot_type(ot_type)
{
}

void OSNReceiver::init(size_t size, int ot_type)
{
	this->size = size;
	this->ot_type = ot_type;
}

std::vector<oc::block> OSNReceiver::run_osn(std::vector<oc::block> inputs, std::vector<oc::Channel>& chls)
{
	int values = size;
	std::vector<std::vector<block>> ret_masks = gen_benes_client_osn(values, chls);
	std::vector<block> output_masks, benes_input;

	for (int i = 0; i < values; ++i)
		ret_masks[i][0] = ret_masks[i][0] ^ inputs[i];
	for (int i = 0; i < values; ++i)
		benes_input.push_back(ret_masks[i][0]);
	chls[0].send(benes_input);
	for (int i = 0; i < values; ++i)
		output_masks.push_back(ret_masks[i][1]);
	return output_masks;
}

std::vector<oc::block> OSNReceiver::run_osn_arithmetic(
	std::vector<oc::block> inputs, std::vector<oc::Channel>& chls, uint64_t modulus)
{
	if (modulus < 2) throw std::invalid_argument("arithmetic OSN modulus must be at least 2");
	int values = size;
	auto ret_masks = gen_benes_client_osn(values, chls, modulus);
	std::vector<block> output_masks, benes_input;
	benes_input.reserve(values);
	output_masks.reserve(values);
	for (int i = 0; i < values; ++i) {
		const uint64_t x = block_word(inputs[i]) % modulus;
		const uint64_t mask = block_word(ret_masks[i][0]) % modulus;
		benes_input.push_back(word_block(sub_mod(x, mask, modulus)));
		output_masks.push_back(ret_masks[i][1]);
	}
	chls[0].send(benes_input);
	return output_masks;
}

void OSNReceiver::setTimer(Timer& timer)
{
	this->timer = &timer;
}

void OSNReceiver::prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<oc::block>& src,
	std::vector<std::array<std::array<osuCrypto::block, 2>, 2>>& ot_output,
	std::vector<std::array<osuCrypto::block, 2>>& correction_blocks,
	uint64_t modulus)
{
	// ot message M0 = m0 ^ w0 || m1 ^ w1
	//  for each switch: top wire m0 w0 - bottom wires m1, w1
	//  M1 = m0 ^ w1 || m1 ^ w0
	int levels = 2 * n - 1, base_idx;
	int values = src.size();
	std::vector<block> bottom1;
	std::vector<block> top1;

	block m0, m1, w0, w1, M0[2], M1[2], corr_mesg[2];
	std::array<oc::block, 2> corr_block, temp_block;

	if (values == 2)
	{
		if (n == 1)
		{
			base_idx = lvl_p * (Val / 2) + perm_idx;
			m0 = src[0];
			m1 = src[1];
			temp_block = ot_output[base_idx][0];
			memcpy(M0, temp_block.data(), sizeof(M0));
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		prepare_switch_shares(m0, m1, {M0[0], M0[1]}, {M1[0], M1[1]},
			modulus, w0, w1, corr_block, temp_block);
		correction_blocks[base_idx] = corr_block;
		ot_output[base_idx][1] = temp_block;
			src[0] = w0;
			src[1] = w1;
		}
		else
		{
			base_idx = (lvl_p + 1) * (Val / 2) + perm_idx;
			m0 = src[0];
			m1 = src[1];
			temp_block = ot_output[base_idx][0];
			memcpy(M0, temp_block.data(), sizeof(M0));
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		prepare_switch_shares(m0, m1, {M0[0], M0[1]}, {M1[0], M1[1]},
			modulus, w0, w1, corr_block, temp_block);
		correction_blocks[base_idx] = corr_block;
		ot_output[base_idx][1] = temp_block;
			src[0] = w0;
			src[1] = w1;
		}
		return;
	}

	if (values == 3)
	{
		base_idx = lvl_p * (Val / 2) + perm_idx;
		m0 = src[0];
		m1 = src[1];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		prepare_switch_shares(m0, m1, {M0[0], M0[1]}, {M1[0], M1[1]},
			modulus, w0, w1, corr_block, temp_block);
		correction_blocks[base_idx] = corr_block;
		ot_output[base_idx][1] = temp_block;
		src[0] = w0;
		src[1] = w1;

		base_idx = (lvl_p + 1) * (Val / 2) + perm_idx;
		m0 = src[1];
		m1 = src[2];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		prepare_switch_shares(m0, m1, {M0[0], M0[1]}, {M1[0], M1[1]},
			modulus, w0, w1, corr_block, temp_block);
		correction_blocks[base_idx] = corr_block;
		ot_output[base_idx][1] = temp_block;
		src[1] = w0;
		src[2] = w1;

		base_idx = (lvl_p + 2) * (Val / 2) + perm_idx;
		m0 = src[0];
		m1 = src[1];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		prepare_switch_shares(m0, m1, {M0[0], M0[1]}, {M1[0], M1[1]},
			modulus, w0, w1, corr_block, temp_block);
		correction_blocks[base_idx] = corr_block;
		ot_output[base_idx][1] = temp_block;
		src[0] = w0;
		src[1] = w1;
		return;
	}

	// partea superioara
	for (int i = 0; i < values - 1; i += 2)
	{
		base_idx = (lvl_p) * (Val / 2) + perm_idx + i / 2;
		m0 = src[i];
		m1 = src[i ^ 1];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		prepare_switch_shares(m0, m1, {M0[0], M0[1]}, {M1[0], M1[1]},
			modulus, w0, w1, corr_block, temp_block);
		correction_blocks[base_idx] = corr_block;
		ot_output[base_idx][1] = temp_block;
		src[i] = w0;
		src[i ^ 1] = w1;

		bottom1.push_back(src[i]);
		top1.push_back(src[i ^ 1]);
	}

	if (values % 2 == 1)
	{
		top1.push_back(src[values - 1]);
	}

	cpus--;
	thread top_thrd, btm_thrd;
	if (cpus > 0)
	{
		top_thrd = thread(&OSNReceiver::prepare_correction, this, n - 1, Val, lvl_p + 1, perm_idx + values / 4, std::ref(top1), std::ref(ot_output), std::ref(correction_blocks), modulus);
	}
	else
	{
		prepare_correction(n - 1, Val, lvl_p + 1, perm_idx + values / 4, top1, ot_output, correction_blocks, modulus);
	}
	if (cpus > 0)
	{
		btm_thrd = thread(&OSNReceiver::prepare_correction, this, n - 1, Val, lvl_p + 1, perm_idx, std::ref(bottom1), std::ref(ot_output), std::ref(correction_blocks), modulus);
	}
	else
	{
		prepare_correction(n - 1, Val, lvl_p + 1, perm_idx, bottom1, ot_output, correction_blocks, modulus);
	}
	if (top_thrd.joinable())
		top_thrd.join();
	if (btm_thrd.joinable())
		btm_thrd.join();
	cpus++;

	// partea inferioara
	for (int i = 0; i < values - 1; i += 2)
	{
		base_idx = (lvl_p + levels - 1) * (Val / 2) + perm_idx + i / 2;
		m1 = top1[i / 2];
		m0 = bottom1[i / 2];
		temp_block = ot_output[base_idx][0];
		memcpy(M0, temp_block.data(), sizeof(M0));
		temp_block = ot_output[base_idx][1];
		memcpy(M1, temp_block.data(), sizeof(M1));
		prepare_switch_shares(m0, m1, {M0[0], M0[1]}, {M1[0], M1[1]},
			modulus, w0, w1, corr_block, temp_block);
		correction_blocks[base_idx] = corr_block;
		ot_output[base_idx][1] = temp_block;
		src[i] = w0;
		src[i ^ 1] = w1;
	}

	int idx = int(ceil(values * 0.5));
	if (values % 2 == 1)
	{
		src[values - 1] = top1[idx - 1];
	}
}
