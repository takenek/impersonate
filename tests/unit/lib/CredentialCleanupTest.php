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

namespace OCA\Impersonate\Tests\Unit\Lib;

use OC\Authentication\Exceptions\InvalidTokenException;
use OC\Authentication\Token\DefaultToken;
use OC\Authentication\Token\DefaultTokenProvider;
use OC\Authentication\Token\IToken;
use OCA\Impersonate\AuditTrail;
use OCA\Impersonate\CredentialCleanup;
use OCA\Impersonate\Notifier;
use OCP\IConfig;
use OCP\ILogger;
use OCP\IUser;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class CredentialCleanupTest extends TestCase {
	/** @var DefaultTokenProvider|MockObject */
	private $tokenProvider;
	/** @var IConfig|MockObject */
	private $config;
	/** @var AuditTrail|MockObject */
	private $auditTrail;
	/** @var ILogger|MockObject */
	private $logger;
	/** @var CredentialCleanup */
	private $cleanup;
	/** @var IUser|MockObject */
	private $alice;
	/** @var DefaultToken[] tokens of alice */
	private $tokens = [];
	/** @var int[] */
	private $revoked = [];
	/** @var string */
	private $signingKey = '';
	/** @var callable|null called after a token was revoked */
	private $onRevoke;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->createMock(IUser::class);
		$this->alice->method('getUID')->willReturn('alice');
		$this->tokenProvider = $this->createMock(DefaultTokenProvider::class);
		$this->tokenProvider->method('getTokenByUser')->willReturnCallback(function () {
			return $this->tokens;
		});
		$this->tokenProvider->method('invalidateTokenById')->willReturnCallback(function (IUser $user, $id) {
			$this->assertSame('alice', $user->getUID());
			$this->revoked[] = $id;
			$this->tokens = \array_values(\array_filter($this->tokens, function (DefaultToken $token) use ($id) {
				return $token->getId() !== $id;
			}));
			if ($this->onRevoke !== null) {
				($this->onRevoke)($id);
			}
		});
		$this->config = $this->createMock(IConfig::class);
		$this->config->method('getUserValue')->willReturnCallback(function ($uid, $app, $key, $default = '') {
			$this->assertSame(['alice', 'core', 'signing-key'], [$uid, $app, $key]);
			return $this->signingKey;
		});
		$this->config->method('deleteUserValue')->willReturnCallback(function () {
			$this->signingKey = '';
		});
		$this->auditTrail = $this->createMock(AuditTrail::class);
		$this->logger = $this->createMock(ILogger::class);
		$this->cleanup = new CredentialCleanup($this->tokenProvider, $this->config, $this->auditTrail, $this->logger);
	}

	private function token(int $id, int $type, bool $withPassword, string $name): DefaultToken {
		$token = new DefaultToken();
		$token->setId($id);
		$token->setUid('alice');
		$token->setType($type);
		$token->setName($name);
		if ($withPassword) {
			$token->setPassword('encrypted');
		}
		return $this->tokens[] = $token;
	}

	private const DONE = ['tokens' => true, 'signingKey' => true];

	/**
	 * @return array{tokens: bool, signingKey: bool} the result without the ceiling
	 */
	private static function done(array $result): array {
		return ['tokens' => $result['tokens'], 'signingKey' => $result['signingKey']];
	}

	public function testOnlyTokensWithoutAPasswordAboveTheMarkAreRevoked(): void {
		$this->token(40, IToken::PERMANENT_TOKEN, false, 'older than the impersonation');
		$this->token(41, IToken::TEMPORARY_TOKEN, false, 'an older session');
		// the session token of the impersonation itself is the mark (it is revoked by its id)
		$this->token(50, IToken::TEMPORARY_TOKEN, false, 'Impersonated by admin');
		$this->token(51, IToken::PERMANENT_TOKEN, false, 'minted');
		$this->token(52, IToken::PERMANENT_TOKEN, true, 'created by the owner with the password');
		$this->token(53, IToken::TEMPORARY_TOKEN, true, 'a session of the owner with the password');
		$this->token(54, IToken::PERMANENT_TOKEN, false, 'minted too');
		// e.g. a login that used the session id of the impersonation as its password
		$this->token(55, IToken::TEMPORARY_TOKEN, false, 'derived');
		$this->auditTrail->expects($this->exactly(3))->method('credentialRevoked')->withConsecutive(
			['alice', 'minted', 'admin', Notifier::CREDENTIAL_APP_PASSWORD],
			['alice', 'minted too', 'admin', Notifier::CREDENTIAL_APP_PASSWORD],
			// what it is travels separately from its name: the notification says it in the owner's language
			['alice', 'derived', 'admin', Notifier::CREDENTIAL_SESSION]
		);
		$this->logger->expects($this->exactly(3))->method('warning')->withConsecutive(
			[$this->stringContains('app password')],
			[$this->stringContains('app password')],
			[$this->stringContains('Revoked passwordless session')]
		);

		$result = $this->cleanup->run($this->alice, 50, true, 'admin');
		$this->assertSame(self::DONE, self::done($result));
		$this->assertSame(53, $result['ceiling'], 'the highest token id that is left: later tokens are out of reach');
		$this->assertSame([51, 54, 55], $this->revoked);
	}

	public function testTheSessionTokensOfOtherImpersonationsAreLeftAlone(): void {
		// the same user is impersonated again (or by somebody else) before the first cleanup runs
		$this->token(50, IToken::TEMPORARY_TOKEN, false, 'Impersonated by admin');
		$this->token(51, IToken::PERMANENT_TOKEN, false, 'minted');
		$other = $this->token(60, IToken::TEMPORARY_TOKEN, false, 'Impersonated by carol');
		$this->auditTrail->expects($this->once())->method('credentialRevoked')->with('alice', 'minted', 'admin');

		$result = $this->cleanup->run($this->alice, 50, true, 'admin', null, [60, 70]);
		$this->assertSame(self::DONE, self::done($result));
		$this->assertSame([51], $this->revoked);
		$this->assertContains($other, $this->tokens);
	}

	public function testTokensThatAppearWhileTheCleanupRunsAreRevokedAsWell(): void {
		// a session that is revoked here created another one a moment before
		$this->token(51, IToken::TEMPORARY_TOKEN, false, 'derived');
		$this->onRevoke = function ($id) {
			if ($id === 51) {
				$this->token(52, IToken::TEMPORARY_TOKEN, false, 'derived from the derived one');
			}
		};
		$result = $this->cleanup->run($this->alice, 50, true, 'admin');
		$this->assertSame([51, 52], $this->revoked);
		$this->assertSame(self::DONE, self::done($result));
		$this->assertSame(50, $result['ceiling']);
	}

	public function testACleanupThatNeverComesToAnEndIsReportedAsIncomplete(): void {
		// something keeps creating tokens: no ceiling can be set yet
		$this->token(51, IToken::TEMPORARY_TOKEN, false, 'derived');
		$this->onRevoke = function ($id) {
			$this->token($id + 1, IToken::TEMPORARY_TOKEN, false, 'another one');
		};
		$result = $this->cleanup->run($this->alice, 50, true, 'admin');
		$this->assertSame(['tokens' => false, 'signingKey' => true, 'ceiling' => null], $result);
		$this->assertCount(4, $this->revoked, 'a bounded number of passes');
	}

	public function testTokensThatAppearedAfterTheEndAreLeftAlone(): void {
		// a retry of a cleanup: the owner created an app password after the impersonation had ended
		$this->token(51, IToken::PERMANENT_TOKEN, false, 'minted');
		$this->token(60, IToken::PERMANENT_TOKEN, false, 'created by the owner later');
		$this->auditTrail->expects($this->once())->method('credentialRevoked')->with('alice', 'minted', 'admin');

		$result = $this->cleanup->run($this->alice, 50, true, 'admin', 54);
		$this->assertSame([51], $this->revoked);
		$this->assertSame(54, $result['ceiling'], 'the ceiling does not move');
	}

	public function testASigningKeyThatAppearedIsRemoved(): void {
		$this->signingKey = 'created-while-impersonating';
		$this->auditTrail->expects($this->once())->method('credentialRevoked')
			->with('alice', '', 'admin', Notifier::CREDENTIAL_SIGNING_KEY);
		$this->assertSame(self::DONE, self::done($this->cleanup->run($this->alice, 0, false, 'admin')));
		$this->assertSame('', $this->signingKey);
	}

	public function testASigningKeyThatExistedIsKept(): void {
		$this->signingKey = 'existing';
		$this->auditTrail->expects($this->never())->method('credentialRevoked');
		$this->assertSame(self::DONE, self::done($this->cleanup->run($this->alice, 0, true, 'admin')));
		$this->assertSame('existing', $this->signingKey);
	}

	public function testNothingToDo(): void {
		$this->auditTrail->expects($this->never())->method('credentialRevoked');
		$result = $this->cleanup->run($this->alice, 7, false, null);
		$this->assertSame(self::DONE, self::done($result));
		$this->assertSame(7, $result['ceiling']);
		$this->assertSame([], $this->revoked);
	}

	public function testTokensThatCanNotBeListedAreReportedSoThatTheCleanupIsRetried(): void {
		$tokenProvider = $this->createMock(DefaultTokenProvider::class);
		$tokenProvider->method('getTokenByUser')->willThrowException(new \RuntimeException('token backend down'));
		$this->signingKey = 'created-while-impersonating';
		$this->logger->expects($this->once())->method('logException');
		$cleanup = new CredentialCleanup($tokenProvider, $this->config, $this->auditTrail, $this->logger);
		$result = $cleanup->run($this->alice, 0, false, 'admin');
		$this->assertSame(['tokens' => false, 'signingKey' => true, 'ceiling' => null], $result);
		$this->assertSame('', $this->signingKey, 'the part that works is done');
	}

	public function testATokenThatCanNotBeRevokedIsReportedAndTheOthersAreStillRevoked(): void {
		$this->token(51, IToken::PERMANENT_TOKEN, false, 'first');
		$this->token(52, IToken::PERMANENT_TOKEN, false, 'second');
		$tokenProvider = $this->createMock(DefaultTokenProvider::class);
		$tokenProvider->method('getTokenByUser')->willReturn($this->tokens);
		$tokenProvider->method('invalidateTokenById')->willReturnCallback(function (IUser $user, $id) {
			if ($id === 51) {
				throw new \RuntimeException('token backend hiccup');
			}
			$this->revoked[] = $id;
		});
		// only what was really revoked is announced
		$this->auditTrail->expects($this->once())->method('credentialRevoked')->with('alice', 'second', 'admin');
		$cleanup = new CredentialCleanup($tokenProvider, $this->config, $this->auditTrail, $this->logger);
		$result = $cleanup->run($this->alice, 50, true, 'admin');
		// what could not be revoked may still create tokens: nothing is out of reach of the retry yet
		$this->assertSame(['tokens' => false, 'signingKey' => true, 'ceiling' => null], $result);
		$this->assertSame([52], $this->revoked);
	}

	public function testACeilingOfAnEarlierRunStaysWhenARevocationFails(): void {
		$this->token(51, IToken::PERMANENT_TOKEN, false, 'first');
		$this->token(53, IToken::PERMANENT_TOKEN, false, 'created after the end');
		$tokenProvider = $this->createMock(DefaultTokenProvider::class);
		$tokenProvider->method('getTokenByUser')->willReturn($this->tokens);
		$tokenProvider->method('invalidateTokenById')->willThrowException(new \RuntimeException('token backend hiccup'));
		$this->auditTrail->expects($this->never())->method('credentialRevoked');
		$cleanup = new CredentialCleanup($tokenProvider, $this->config, $this->auditTrail, $this->logger);
		$this->assertSame(
			['tokens' => false, 'signingKey' => true, 'ceiling' => 52],
			$cleanup->run($this->alice, 50, true, 'admin', 52)
		);
	}

	public function testEveryTokenIsRevokedBeforeAnyOfThemIsAnnounced(): void {
		// a session that is to be revoked gets no time to create another one while the first is announced
		$this->token(51, IToken::TEMPORARY_TOKEN, false, 'derived');
		$this->token(52, IToken::PERMANENT_TOKEN, false, 'minted');
		$sequence = [];
		$this->onRevoke = function ($id) use (&$sequence) {
			$sequence[] = "revoke $id";
		};
		$this->auditTrail->method('credentialRevoked')->willReturnCallback(function ($uid, $name, $impersonator, $kind) use (&$sequence) {
			$sequence[] = "announce $kind $name";
		});
		$this->cleanup->run($this->alice, 50, true, 'admin');
		$this->assertSame(['revoke 51', 'revoke 52', 'announce session derived', 'announce app_password minted'], $sequence);
	}

	public function testAFailingSigningKeyRemovalIsReported(): void {
		$config = $this->createMock(IConfig::class);
		$config->method('getUserValue')->willThrowException(new \RuntimeException('config backend down'));
		$cleanup = new CredentialCleanup($this->tokenProvider, $config, $this->auditTrail, $this->logger);
		$this->assertSame(['tokens' => true, 'signingKey' => false], self::done($cleanup->run($this->alice, 0, false, 'admin')));
		// not asked at all when the user had a key before
		$this->assertSame(self::DONE, self::done($cleanup->run($this->alice, 0, true, 'admin')));
	}

	public function testAUserWithMoreTokensThanThePlatformListsIsReported(): void {
		for ($id = 1; $id <= 1000; $id++) {
			$this->token($id, IToken::TEMPORARY_TOKEN, true, 'session');
		}
		$this->logger->expects($this->once())->method('error')->with($this->stringContains('so many tokens'));
		$this->cleanup->run($this->alice, 0, true, 'admin');
	}

	public function testSigningKeyStateAtTheStart(): void {
		$this->assertFalse($this->cleanup->hasSigningKey($this->alice));
		$this->signingKey = 'key';
		$this->assertTrue($this->cleanup->hasSigningKey($this->alice));
	}

	public function testTheSessionTokenIsKnownByItsIdOnly(): void {
		// the name of a token is free text and decides nothing
		$this->token(60, IToken::TEMPORARY_TOKEN, false, 'renamed by somebody');
		$this->assertTrue($this->cleanup->hasSessionToken($this->alice, 60));
		$this->assertFalse($this->cleanup->hasSessionToken($this->alice, 61));
	}

	public function testATokenThatIsNotInAListThatMayBeIncompleteCountsAsPresent(): void {
		// its absence can not be told: a healthy impersonation must not be ended for it
		for ($id = 1; $id <= 1000; $id++) {
			$this->token($id, IToken::TEMPORARY_TOKEN, true, 'session');
		}
		$this->assertTrue($this->cleanup->hasSessionToken($this->alice, 5000));
	}

	public function testRevokeSessionToken(): void {
		$this->assertTrue($this->cleanup->revokeSessionToken($this->alice, 60));
		$this->assertSame([60], $this->revoked);
	}

	public function testAFailingRevocationIsReported(): void {
		$tokenProvider = $this->createMock(DefaultTokenProvider::class);
		$tokenProvider->method('invalidateTokenById')->willThrowException(new \RuntimeException('token backend down'));
		$this->logger->expects($this->once())->method('logException');
		$cleanup = new CredentialCleanup($tokenProvider, $this->config, $this->auditTrail, $this->logger);
		$this->assertFalse($cleanup->revokeSessionToken($this->alice, 60));
	}

	public function testFindToken(): void {
		$token = $this->token(60, IToken::TEMPORARY_TOKEN, false, 'Impersonated by admin');
		$tokenProvider = $this->createMock(DefaultTokenProvider::class);
		$tokenProvider->method('getToken')->willReturnCallback(function ($secret) use ($token) {
			if ($secret !== 'the-session-id') {
				throw new InvalidTokenException();
			}
			return $token;
		});
		$cleanup = new CredentialCleanup($tokenProvider, $this->config, $this->auditTrail, $this->logger);
		$this->assertSame(['id' => 60, 'uid' => 'alice'], $cleanup->findToken('the-session-id'));
		$this->assertNull($cleanup->findToken('something else'));
		$this->assertNull($cleanup->findToken(''));
	}
}
