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
 */
class L10nTest extends TestCase {
	private static function l10nDir(): string {
		return \dirname(__DIR__, 2) . '/l10n';
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

	public function testThereAreTranslations(): void {
		$this->assertGreaterThan(30, \count(self::localeProvider()));
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
