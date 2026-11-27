<?php
/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/impersonate
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and the AGPL section 7 attribution terms.
 *
 * @author    Marek Królikowski (TaKeN)
 * @link      https://github.com/takenek
 * @license   AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU Affero General Public License as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 */

namespace OCA\Impersonate\Tests\Unit;

use Test\TestCase;

/**
 * The translations are filled into the page by name: "{currentUser}" in the
 * source text must be "{currentUser}" in every translation, otherwise e.g. the
 * banner does not show whom the session impersonates.
 *
 * A text without a translation is shown in English. Every translation of the
 * app is complete, so that must not happen: a dialog would be half translated,
 * e.g. the confirmation that names the account to impersonate.
 *
 * The app has a translation for every language ownCloud offers (core/l10n):
 * ownCloud uses the translation of an app only for exactly the language of the
 * user; without it the app would appear in the default language of the
 * instance, in the language of the browser or in English instead.
 */
class L10nTest extends TestCase {
	private static function appDir(): string {
		return \dirname(__DIR__, 2);
	}

	private static function l10nDir(): string {
		return self::appDir() . '/l10n';
	}

	/**
	 * How the code passes a text to the translation functions, per kind of source: the pattern of a
	 * call with a text the test can read (a single-quoted literal), the pattern of any call, and the
	 * files. JavaScript: t('impersonate', '...'); PHP: ->t('...').
	 */
	private const CALLS = [
		[
			'/\bt\(\s*\'impersonate\',\s*\'((?:[^\'\\\\]|\\\\.)*)\'/s',
			'/\b[tn]\(\s*[\'"`]impersonate[\'"`]/',
			['js/*.js'],
		],
		[
			'/->t\(\s*\'((?:[^\'\\\\]|\\\\.)*)\'/s',
			'/->[tn]\(/',
			['appinfo/*.php', 'controller/*.php', 'lib/*.php', 'lib/*/*.php', 'templates/*.php'],
		],
	];

	/**
	 * @return string[] the files of the given globs
	 */
	private static function files(array $globs): array {
		$files = [];
		foreach ($globs as $glob) {
			foreach (\glob(self::appDir() . '/' . $glob) ?: [] as $file) {
				$files[] = $file;
			}
		}
		return $files;
	}

	/**
	 * @return string[] the texts the code passes to the translation functions
	 */
	private static function sourceTexts(): array {
		$texts = [];
		foreach (self::CALLS as [$pattern, , $globs]) {
			foreach (self::files($globs) as $file) {
				\preg_match_all($pattern, (string)\file_get_contents($file), $matches);
				foreach ($matches[1] as $text) {
					// the text as the code means it: without the escaping of the string literal
					$texts[\strtr($text, ["\\'" => "'", '\\\\' => '\\'])] = true;
				}
			}
		}
		return \array_map('strval', \array_keys($texts));
	}

	/**
	 * @return string[] placeholders "{name}" and "%s" style of a text, sorted
	 */
	private static function placeholders(string $text): array {
		\preg_match_all('/\{[^{}\s]*\}|%(?:\d+\$)?[sdn]/u', $text, $matches);
		$placeholders = $matches[0];
		\sort($placeholders);
		return $placeholders;
	}

	public static function localeProvider(): array {
		$locales = [];
		foreach (\glob(self::l10nDir() . '/*.json') ?: [] as $file) {
			$locales[\basename($file, '.json')] = [\basename($file, '.json')];
		}
		return $locales;
	}

	/**
	 * @return array<string, string> locale => plural form of ownCloud core (core/l10n/<locale>.json)
	 */
	private static function coreLocales(): array {
		$locales = [];
		foreach (\glob(\OC::$SERVERROOT . '/core/l10n/*.json') ?: [] as $file) {
			$json = \json_decode((string)\file_get_contents($file), true);
			$locales[\basename($file, '.json')] = \is_array($json) ? (string)($json['pluralForm'] ?? '') : '';
		}
		\ksort($locales);
		return $locales;
	}

	/**
	 * Whether ownCloud (core, settings or lib) translates the text into the locale, or into its
	 * language without the country or script part (es_ES: es), with the same words.
	 */
	private static function ownCloudKeepsTheText(string $locale, string $text): bool {
		$language = (string)\preg_replace('/[_@-].*$/', '', $locale);
		foreach (\array_unique([$locale, $language]) as $code) {
			foreach (['core', 'settings', 'lib'] as $part) {
				$json = \json_decode((string)@\file_get_contents(\OC::$SERVERROOT . "/$part/l10n/$code.json"), true);
				$translation = \is_array($json) ? ($json['translations'][$text] ?? null) : null;
				if (\is_array($translation)) {
					$translation = $translation[0] ?? null;
				}
				if ($translation === $text) {
					return true;
				}
			}
		}
		return false;
	}

	public function testEveryLanguageOfOwnCloudHasATranslation(): void {
		$core = \array_keys(self::coreLocales());
		$this->assertGreaterThan(100, \count($core), 'the languages of ownCloud core were not found');
		$app = \array_keys(self::localeProvider());
		\sort($app);
		$this->assertSame([], \array_values(\array_diff($core, $app)), 'languages of ownCloud without a translation of the app');
		$this->assertSame([], \array_values(\array_diff($app, $core)), 'translations of the app for a language ownCloud does not have');
	}

	/**
	 * @dataProvider localeProvider
	 */
	public function testThePluralFormIsTheOneOfOwnCloud(string $locale): void {
		$json = \json_decode((string)\file_get_contents(self::l10nDir() . "/$locale.json"), true);
		$core = self::coreLocales()[$locale] ?? null;
		$this->assertIsString($core, "$locale: ownCloud core has no plural form");
		if (\substr_count($core, '(') === \substr_count($core, ')') + 1 && \substr($core, -1) === ';') {
			// ownCloud 11.1.0 has an unclosed parenthesis in the form of tzm, which the browser can not
			// compile (an error on every page): the app closes it
			$core = \substr($core, 0, -1) . ');';
		}
		$this->assertSame($core, $json['pluralForm'] ?? null, "$locale.json: the plural form differs from ownCloud core");
	}

	public function testTheTextsOfTheAppAreFound(): void {
		$sources = self::sourceTexts();
		// one of each kind: JavaScript, the controller, a template (with an escaped quote), a class of lib/
		foreach ([
			'Do you want to log in as user "{user}"? Everything you do until you log out is done as this user.',
			'Can not impersonate a disabled user',
			'The group admin feature of this server is disabled (config.php: \'allow_subadmins\' => false), so only administrators can impersonate users. Set \'allow_subadmins\' => true to use the group admin options.',
			'"%s" was revoked for security reasons at the end of an impersonation of your account. If you created it yourself, please create it again.',
		] as $text) {
			$this->assertContains($text, $sources);
		}
	}

	/**
	 * The completeness test below only knows the texts it can read. A call in another form (a text
	 * in double quotes or in a variable, a plural) must not go unnoticed: write it as the others are.
	 */
	public function testEveryTranslationCallHasATextTheTestCanRead(): void {
		foreach (self::CALLS as [$readable, $any, $globs]) {
			foreach (self::files($globs) as $file) {
				$code = (string)\file_get_contents($file);
				$this->assertSame(
					\preg_match_all($any, $code),
					\preg_match_all($readable, $code),
					\basename($file) . ': a translation call whose text is not a single-quoted literal'
				);
			}
		}
	}

	/**
	 * @dataProvider localeProvider
	 */
	public function testATranslationHoldsEveryTextOfTheApp(string $locale): void {
		$json = \json_decode((string)\file_get_contents(self::l10nDir() . "/$locale.json"), true);
		$this->assertIsArray($json['translations'] ?? null);
		$translations = $json['translations'];
		$sources = self::sourceTexts();
		$this->assertSame(
			[],
			\array_values(\array_diff($sources, \array_keys($translations))),
			"$locale.json: texts of the app without a translation (they would be shown in English)"
		);
		$this->assertSame(
			[],
			\array_values(\array_diff(\array_map('strval', \array_keys($translations)), $sources)),
			"$locale.json: translations of texts the app does not use (anymore)"
		);
		foreach ($translations as $source => $translation) {
			$this->assertNotSame('', \trim((string)$translation), "$locale.json: empty translation of \"$source\"");
			// only the English locales keep the source text, and a language in which ownCloud itself
			// translates the text with the same words (e.g. "Error" in Spanish, also es_ES)
			if (\strpos($locale, 'en_') !== 0 && (string)$source === (string)$translation) {
				$this->assertTrue(self::ownCloudKeepsTheText($locale, (string)$source), "$locale.json: \"$source\" is not translated");
			}
		}
	}

	/**
	 * @dataProvider localeProvider
	 */
	public function testPlaceholdersOfTheTranslationsMatchTheSource(string $locale): void {
		$json = \json_decode((string)\file_get_contents(self::l10nDir() . "/$locale.json"), true);
		$this->assertIsArray($json, "$locale.json is not valid JSON");
		$this->assertIsArray($json['translations'] ?? null);
		foreach ($json['translations'] as $source => $translation) {
			$this->assertIsString($translation, "$locale: $source");
			$this->assertSame(
				self::placeholders($source),
				self::placeholders($translation),
				"$locale.json: the placeholders of the translation of \"$source\" differ from the source"
			);
		}
	}

	/**
	 * @dataProvider localeProvider
	 */
	public function testTheJavaScriptFileHoldsTheSameTranslations(string $locale): void {
		$json = \json_decode((string)\file_get_contents(self::l10nDir() . "/$locale.json"), true);
		$js = (string)\file_get_contents(self::l10nDir() . "/$locale.js");
		$this->assertSame(
			1,
			\preg_match('/^OC\.L10N\.register\(\s*"impersonate",\s*(\{.*\}),\s*"([^"]*)"\s*\);\s*$/s', $js, $matches),
			"$locale.js has an unexpected form"
		);
		$this->assertSame($json['translations'], \json_decode($matches[1], true), "$locale.js and $locale.json differ");
		$this->assertSame($json['pluralForm'] ?? null, $matches[2]);
	}
}
