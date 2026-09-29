.PHONY: test contracts python node deploy rollout

test: contracts python node

contracts:
	forge build && forge test --summary

python: contracts
	python3 -m unittest discover -s tests -p 'test_mycomesh_*.py' -v

node:
	npm --prefix packages/mycomesh-cli test

deploy:
	python3 scripts/deploy_v11.py

rollout:
	python3 scripts/rollout_v11.py --cutover
