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

namespace OCA\Impersonate\Tests\Unit\Support;

use OCP\ISession;

/**
 * In-memory session whose id changes on regenerateId(), for unit tests.
 */
class ArraySession implements ISession {
	/** @var array */
	public $data = [];
	/** @var string */
	public $id;
	/** @var string[] ids that were regenerated away */
	public $regenerated = [];

	public function __construct(string $id = 'session-1', array $data = []) {
		$this->id = $id;
		$this->data = $data;
	}

	public function set($key, $value) {
		$this->data[$key] = $value;
	}

	public function get(string $key): mixed {
		return $this->data[$key] ?? null;
	}

	public function exists($key) {
		return \array_key_exists($key, $this->data);
	}

	public function remove($key) {
		unset($this->data[$key]);
	}

	public function clear() {
		$this->data = [];
	}

	public function close() {
	}

	public function regenerateId($deleteOldSession = true) {
		$this->regenerated[] = $this->id;
		$this->id = 'session-' . (\count($this->regenerated) + 1);
	}

	public function getId() {
		return $this->id;
	}
}
