.ONESHELL:

build:
	mkdir -p test/keys
	curl https://traefik.me/fullchain.pem -o test/keys/fullchain.pem
	curl https://traefik.me/privkey.pem -o test/keys/private_key.pem
	docker-compose -f test/docker-compose.yml build


run:
	docker-compose -f test/docker-compose.yml up