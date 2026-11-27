SHELL := /bin/bash

COMPOSER_BIN := $(shell command -v composer 2> /dev/null)

HANDLEBARS=$(CURDIR)/node_modules/handlebars/bin/handlebars
# ownCloud 11 only installs archives whose folder is named exactly like the <id> in info.xml
appname=$(shell sed -n 's:.*<id>\(.*\)</id>.*:\1:p' appinfo/info.xml)
appversion=$(shell sed -n 's:.*<version>\(.*\)</version>.*:\1:p' appinfo/info.xml)
archive=build/$(appname)-$(appversion).tar.gz
# reproducible archives: fixed order, owner, file modes (whatever the umask of the builder is) and
# (with SOURCE_DATE_EPOCH) timestamps
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null)
TAR_REPRO=--sort=name --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' $(if $(SOURCE_DATE_EPOCH),--mtime=@$(SOURCE_DATE_EPOCH))


# composer
acceptance_test_deps=vendor-bin/behat/vendor

# Code signing: ownCloud 11 removed "occ integrity:sign-app"; packages must be signed
# with ownCloud's external G2 signing tooling and a certificate issued by ownCloud.
# Set SIGN_CMD to a command that signs the directory passed as its last argument,
# e.g. make dist SIGN_CMD="/path/to/signer --key ... --cert ...". Unsigned packages
# can still be deployed manually (see README.md).
SIGN_CMD ?=
template_src=$(wildcard js/templates/*.handlebars)
app_namespace=Impersonate
js_namespace=OCA.$(app_namespace)
NODE_PREFIX=$(shell pwd)

NPM := $(shell command -v npm 2> /dev/null)

# bin file definitions
PHPUNIT=php -d zend.enable_gc=0  "$(CURDIR)/../../lib/composer/bin/phpunit"
PHPUNITDBG=phpdbg -qrr -d memory_limit=4096M -d zend.enable_gc=0 "$(CURDIR)/../../lib/composer/bin/phpunit"
PHP_CS_FIXER=php -d zend.enable_gc=0 vendor-bin/owncloud-codestyle/vendor/bin/php-cs-fixer
PHAN=php -d zend.enable_gc=0 vendor-bin/phan/vendor/bin/phan
PHPSTAN=php -d zend.enable_gc=0 vendor-bin/phpstan/vendor/bin/phpstan
BEHAT_BIN=vendor-bin/behat/vendor/bin/behat

all: build

# start with displaying help
help: ## Show this help message
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//' | sed -e 's/  */ /' | column -t -s :

#
# Catch-all rules
#
.PHONY: dist
dist: ## Build the release archive build/impersonate-<version>.tar.gz (+ .sha256)
dist: build-dep clean-templates js-templates build-src

%.js: $(template_src)
		$(HANDLEBARS) -n "$(js_namespace)" $* -f $@

# Installs dependencies and does any build actions needed for the app to run in CI
.PHONY: ci
ci: vendor build-dep js-templates
	@echo dependencies and build actions for CI are completed

.PHONY: build-dep
build-dep: ## fetch all dependencies
build-dep: node_modules

node_modules: package.json package-lock.json
		$(NPM) ci --no-audit --no-fund --prefix=$(NODE_PREFIX) && touch $@

.PHONY: js-templates
js-templates: ## build templates for frontend
js-templates: $(addsuffix .js, $(template_src))

# Installs and updates the composer dependencies.
.PHONY: composer
composer:
	composer install --prefer-dist
	composer update --prefer-dist

# Fetches the PHP and JS dependencies and compiles the JS. If no composer.json
# is present, the composer step is skipped, if no package.json or js/package.json
# is present, the npm step is skipped
.PHONY: build
build:
ifneq (,$(wildcard $(CURDIR)/composer.json))
	make composer
endif

.PHONY: clean
clean: ## Clean
clean: clean-build clean-deps

.PHONY: clean-deps
clean-deps:
	rm -Rf vendor
	rm -Rf vendor-bin/**/vendor

.PHONY: clean-templates
clean-templates:
		rm -f $(addsuffix .js, $(template_src))

.PHONY: build-src

#
# build source package
#
build-src: ## Build source package
	rm -rf build/$(appname) build/$(appname)-*.tar.gz*
	mkdir -p build/$(appname)
	cp --parents -r \
		appinfo \
		controller \
		css \
		img \
		js \
		l10n \
		lib \
		README.md \
		SECURITY.md \
		LICENSE \
		COPYRIGHT \
		AUTHORS.md \
		CHANGELOG.md \
		templates \
		build/$(appname)
	rm -Rf build/$(appname)/js/templates/*.handlebars build/$(appname)/l10n/.tx
ifneq (,$(SIGN_CMD))
	$(SIGN_CMD) "$(CURDIR)/build/$(appname)"
else
	@echo "Skipping signing (SIGN_CMD not set). See README.md for installing an unsigned package on ownCloud 11."
endif
	tar --format=gnu $(TAR_REPRO) -cf - -C $(CURDIR)/build $(appname) | gzip -9n > $(archive)
	cd build && sha256sum $(notdir $(archive)) > $(notdir $(archive)).sha256
	@echo "built $(archive)"

.PHONY: clean-build
clean-build:
		rm -fR build
		rm -f $(addsuffix .js, $(template_src))
		rm -fr $(NODE_PREFIX)/node_modules


##---------------------
## Tests
##---------------------

.PHONY: test-php-unit
test-php-unit: ## Run php unit tests
test-php-unit:
	$(PHPUNIT) --configuration ./phpunit.xml --testsuite unit

.PHONY: test-php-unit-dbg
test-php-unit-dbg: ## Run php unit tests using phpdbg
test-php-unit-dbg:
	$(PHPUNITDBG) --configuration ./phpunit.xml --testsuite unit

.PHONY: test-php-style
test-php-style: ## Run php-cs-fixer and check owncloud code-style
test-php-style: vendor-bin/owncloud-codestyle/vendor
	$(PHP_CS_FIXER) fix -v --diff --allow-risky yes --dry-run

.PHONY: test-php-style-fix
test-php-style-fix: ## Run php-cs-fixer and fix code style issues
test-php-style-fix: vendor-bin/owncloud-codestyle/vendor
	$(PHP_CS_FIXER) fix -v --diff --allow-risky yes

.PHONY: test-php-phan
test-php-phan: ## Run phan
test-php-phan: vendor-bin/phan/vendor
	$(PHAN) --config-file .phan/config.php --require-config-exists

.PHONY: test-php-phpstan
test-php-phpstan: ## Run phpstan
test-php-phpstan: vendor-bin/phpstan/vendor
	$(PHPSTAN) analyse --memory-limit=4G --configuration=./phpstan.neon --no-progress --level=5 appinfo controller lib

.PHONY: test-acceptance-api
test-acceptance-api: ## Run API acceptance tests
test-acceptance-api: $(acceptance_test_deps)
	BEHAT_BIN=$(BEHAT_BIN) ../../tests/acceptance/run.sh --remote --type api

.PHONY: test-acceptance-cli
test-acceptance-cli: ## Run CLI acceptance tests
test-acceptance-cli:
	BEHAT_BIN=$(BEHAT_BIN) ../../tests/acceptance/run.sh --remote --type cli

.PHONY: test-acceptance-webui
test-acceptance-webui:  ## Run webUI acceptance tests
test-acceptance-webui: $(acceptance_test_deps)
	BEHAT_BIN=$(BEHAT_BIN) ../../tests/acceptance/run.sh --remote --type webUI


#
# Dependency management
#--------------------------------------

composer.lock: composer.json
	@echo composer.lock is not up to date.

vendor: composer.lock
	$(COMPOSER_BIN) install --no-dev

vendor/bamarni/composer-bin-plugin: composer.lock
	$(COMPOSER_BIN) install

vendor-bin/owncloud-codestyle/vendor: vendor/bamarni/composer-bin-plugin vendor-bin/owncloud-codestyle/composer.lock
	$(COMPOSER_BIN) bin owncloud-codestyle install --no-progress

vendor-bin/owncloud-codestyle/composer.lock: vendor-bin/owncloud-codestyle/composer.json
	@echo owncloud-codestyle composer.lock is not up to date.

vendor-bin/phan/vendor: vendor/bamarni/composer-bin-plugin vendor-bin/phan/composer.lock
	$(COMPOSER_BIN) bin phan install --no-progress

vendor-bin/phan/composer.lock: vendor-bin/phan/composer.json
	@echo phan composer.lock is not up to date.

vendor-bin/phpstan/vendor: vendor/bamarni/composer-bin-plugin vendor-bin/phpstan/composer.lock
	$(COMPOSER_BIN) bin phpstan install --no-progress

vendor-bin/phpstan/composer.lock: vendor-bin/phpstan/composer.json
	@echo phpstan composer.lock is not up to date.

vendor-bin/behat/vendor: vendor/bamarni/composer-bin-plugin vendor-bin/behat/composer.lock
	$(COMPOSER_BIN) bin behat install --no-progress

vendor-bin/behat/composer.lock: vendor-bin/behat/composer.json
	@echo behat composer.lock is not up to date.
