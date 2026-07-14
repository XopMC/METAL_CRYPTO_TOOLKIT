PROJECTS := \
	cardano_address_to_hex \
	algorand_address_to_hex \
	multicoin_base58_bech32_address_to_hex \
	base64_data_to_hex \
	cosmos_bnb_address_to_hex \
	polkadot_kusama_address_to_hex \
	filecoin_address_to_hex \
	solana_address_to_hex \
	stellar_address_to_hex \
	stacks_address_to_hex \
	ton_address_to_hex \
	tron_address_to_hex \
	xrp_address_to_hex \
	tezos_address_to_hex \
	profanity_basepoint_generator

CLEAN_TARGETS := $(addsuffix .clean,$(PROJECTS))

.PHONY: all clean $(PROJECTS) $(CLEAN_TARGETS)

all: $(PROJECTS)

$(PROJECTS):
	$(MAKE) -C $@ all

clean: $(CLEAN_TARGETS)

$(CLEAN_TARGETS):
	$(MAKE) -C $(@:.clean=) clean
