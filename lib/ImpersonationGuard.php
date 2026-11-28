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

namespace OCA\Impersonate;

use OCP\IConfig;
use OCP\ILogger;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;

/**
 * Request level checks while a session is impersonating somebody.
 * Runs (from appinfo/app.php) once all authentication apps are loaded and the
 * session was validated by core, before the request is routed.
 *
 * The checks fail closed: a request whose check can not be completed is
 * refused - also when the guard itself can not be built (statusWithoutGuard()),
 * and an impersonation is not started in a request the guard has not seen
 * (isActiveForThisRequest()).
 *
 * An impersonation is known by two things: the marker in its session and the
 * server side record of its session token (ActiveImpersonations). The platform
 * accepts the id of a session as a token credential of its user, so the token
 * of an impersonated session could be presented in another request, outside
 * the marked session and outside these checks. Such a request is refused and
 * ends the impersonation.
 */
class ImpersonationGuard {
	/** the request may continue */
	public const PROCEED = 0;
	/** the request is one that is forbidden while impersonating (HTTP 403) */
	public const FORBIDDEN_REQUEST = 403;
	/** the impersonation could not be verified (HTTP 503) */
	public const UNVERIFIED = 503;
	/** the session token of an impersonation was presented outside its session (HTTP 401) */
	public const TOKEN_MISUSE = 401;
	/** the impersonation of the session has just been ended by its re-validation (HTTP 401) */
	public const ENDED = 1;

	/** the HTTP status of each refusal */
	private const HTTP_STATUS = [
		self::FORBIDDEN_REQUEST => 403,
		self::UNVERIFIED => 503,
		self::TOKEN_MISUSE => 401,
		self::ENDED => 401,
	];

	/**
	 * Requests that would give the impersonator credentials that outlive the
	 * impersonation: [method or '*', path] (path as matched by the router,
	 * lower-case)
	 */
	private const FORBIDDEN = [
		// core route settings.AuthSettings.create: app passwords
		['POST', '/settings/personal/authtokens'],
		// core route ocs.cloud.getSigningKey: key for pre-signed WebDAV URLs
		['*', '/cloud/user/signing-key'],
		// core login form: it accepts the id of a session as the password of its user and
		// would turn the impersonated session into a new session that nothing knows about
		['POST', '/login'],
	];
	/** path prefixes forbidden for every method: OAuth2 authorization (refresh tokens) */
	private const FORBIDDEN_PREFIXES = [
		'/apps/oauth2/',
	];
	/** the way back to the impersonator, never refused */
	private const LOGOUT_PATH = '/logout';
	/** more request values in the shape of a session id than this are not looked up: the request is refused */
	private const MAX_PARAMETER_CANDIDATES = 256;
	/**
	 * Entry points whose requests carry a file or a WebDAV document in their body, of any size,
	 * and their credentials in a header: the body is not examined there
	 */
	private const WEBDAV_ENTRY_POINTS = ['remote.php', 'public.php'];

	private const MESSAGES = [
		self::FORBIDDEN_REQUEST => 'This action is not allowed while impersonating a user',
		self::UNVERIFIED => 'The impersonation could not be verified, please retry',
		self::TOKEN_MISUSE => 'The session of an impersonation can not be used as a credential',
		self::ENDED => 'The impersonation has ended, please log in again',
	];
	/** how much of the request path is written to the log */
	private const LOGGED_PATH_LENGTH = 1024;

	/** @var Util */
	private $util;
	/** @var Policy */
	private $policy;
	/** @var IUserSession */
	private $userSession;
	/** @var IUserManager */
	private $userManager;
	/** @var IRequest */
	private $request;
	/** @var ILogger */
	private $logger;
	/** @var ActiveImpersonations */
	private $registry;
	/** @var CredentialCleanup */
	private $cleanup;
	/** @var Reconciler */
	private $reconciler;

	public function __construct(
		Util $util,
		Policy $policy,
		IUserSession $userSession,
		IUserManager $userManager,
		IRequest $request,
		ILogger $logger,
		ActiveImpersonations $registry,
		CredentialCleanup $cleanup,
		Reconciler $reconciler
	) {
		$this->util = $util;
		$this->policy = $policy;
		$this->userSession = $userSession;
		$this->userManager = $userManager;
		$this->request = $request;
		$this->logger = $logger;
		$this->registry = $registry;
		$this->cleanup = $cleanup;
		$this->reconciler = $reconciler;
	}

	/** @var bool the hook ran for this request */
	private static $checked = false;
	/** @var bool the guard was built and checked this request */
	private static $active = false;

	/**
	 * Slot of the 'OC_App::loadedApps' hook (registered in appinfo/app.php): runs
	 * once per request, after all authentication apps (e.g. LDAP group backends)
	 * are loaded and core validated the session, before the request is routed.
	 * The decisions are made in check() and, if the guard can not be built, in
	 * statusWithoutGuard(); this only wires them to the request.
	 *
	 * @codeCoverageIgnore
	 */
	public static function onLoadedApps(): void {
		if (self::$checked) {
			return;
		}
		self::$checked = true;
		if (self::isCommandLine()) {
			// occ and cron.php on the command line: no HTTP request, no credential and no session of a
			// browser to check - and nothing here may keep occ (e.g. app:disable) from working
			return;
		}
		try {
			$application = new AppInfo\Application();
			/** @var ImpersonationGuard $guard */
			$guard = $application->getContainer()->query(self::class);
			self::$active = true;
			$status = $guard->check();
		} catch (\Throwable $e) {
			// the guard itself could not be built
			try {
				\OC::$server->getLogger()->logException($e, ['app' => 'impersonate']);
			} catch (\Throwable $ignored) {
			}
			$session = null;
			$config = null;
			try {
				$session = \OC::$server->getSession();
				$config = \OC::$server->getConfig();
			} catch (\Throwable $ignored) {
			}
			$status = self::statusWithoutGuard($session, $config);
		}
		if ($status !== self::PROCEED) {
			self::refuse($status);
		}
	}

	/**
	 * Is this PHP process a command line one (occ, cron.php run by the system cron)? PHP's
	 * built-in web server ("cli-server") serves HTTP requests and is no command line.
	 */
	public static function isCommandLine(): bool {
		return \in_array(\PHP_SAPI, ['cli', 'phpdbg'], true);
	}

	/**
	 * Was the guard built and did it check this request? An impersonation must not start in a
	 * request it has not seen (the hook may not have been registered or emitted, or the guard
	 * could not be built): it would not see the requests of the impersonation either.
	 */
	public function isActiveForThisRequest(): bool {
		return self::$active;
	}

	/**
	 * The answer to a request when the guard could not be built. The checks fail closed: the
	 * request is refused if its session is (or may be) marked as an impersonation, and while an
	 * impersonation whose session token may still be valid is recorded, or when that can not be
	 * told - whether the request presents that token can not be checked without the guard
	 * (endMisusedImpersonations()). This trades availability for completeness: until the cause
	 * is fixed (see the ownCloud log) or the app is disabled, every request is refused with
	 * HTTP 503 while such a record exists. A record whose session token is known to be revoked
	 * or that can not be read names no credential and refuses nothing.
	 *
	 * Asked without the services of the app (they are what could not be built).
	 *
	 * @param ISession|null $session the session of the request, null if it can not be had
	 * @param IConfig|null $config null if it can not be had
	 * @return int self::PROCEED or self::UNVERIFIED
	 */
	public static function statusWithoutGuard(?ISession $session, ?IConfig $config): int {
		try {
			if ($session === null || $config === null || $session->get(Util::SESSION_IMPERSONATOR) !== null) {
				return self::UNVERIFIED;
			}
			foreach ($config->getAppKeys('impersonate') as $key) {
				if (\is_string($key) && \strpos($key, ActiveImpersonations::PREFIX) === 0
					&& ActiveImpersonations::namesCredential(ActiveImpersonations::decode($config->getAppValue('impersonate', $key, '')))
				) {
					return self::UNVERIFIED;
				}
			}
			return self::PROCEED;
		} catch (\Throwable $e) {
			return self::UNVERIFIED;
		}
	}

	/**
	 * Decide what happens to the current request.
	 *
	 * - A session that does not impersonate: the request proceeds, unless it
	 *   presents the session token of an impersonation (see
	 *   endMisusedImpersonations()).
	 * - The request is on the deny-list: refused. This does not depend on the
	 *   re-validation, so a failing backend can not open the deny-list.
	 * - Otherwise the impersonation is re-validated (and ended if it is not
	 *   valid anymore, see validate()). A request whose impersonation was ended
	 *   that way is refused, except the logout: what the rest of the request
	 *   would do must not depend on how the platform reads the identity after the
	 *   logout.
	 * - A request of the impersonated session must not present the session token
	 *   of another impersonation either.
	 * - Any error on the way: refused.
	 *
	 * @return int self::PROCEED, self::FORBIDDEN_REQUEST, self::TOKEN_MISUSE, self::ENDED or self::UNVERIFIED
	 */
	public function check(): int {
		try {
			if (!$this->util->isImpersonating()) {
				return $this->endMisusedImpersonations() ? self::TOKEN_MISUSE : self::PROCEED;
			}
			if ($this->isForbiddenRequest()) {
				$this->logRefusal();
				return self::FORBIDDEN_REQUEST;
			}
			if (!$this->validate()) {
				return self::normalizedPath($this->request) === self::LOGOUT_PATH ? self::PROCEED : self::ENDED;
			}
			return $this->endMisusedImpersonations($this->util->getRecordId()) ? self::TOKEN_MISUSE : self::PROCEED;
		} catch (RefusedException $e) {
			// A request that is not looked at any further (see presentedParameters()): no error of
			// the app, and nothing an anonymous client should be able to fill the log with.
			try {
				$this->logger->info(
					'Refused {method} {path} (from {remote}): {reason}',
					[
						'app' => 'impersonate',
						'method' => $this->request->getMethod(),
						'path' => self::loggablePath($this->request),
						'remote' => $this->request->getRemoteAddress(),
						'reason' => $e->getMessage(),
					]
				);
			} catch (\Throwable $ignored) {
			}
			return self::UNVERIFIED;
		} catch (\Throwable $e) {
			try {
				$this->logger->logException($e, ['app' => 'impersonate']);
			} catch (\Throwable $ignored) {
			}
			// The session impersonates and its check failed, or it could not be found out
			// whether the request has to do with an impersonation at all. Refuse.
			return self::UNVERIFIED;
		}
	}

	/**
	 * A request that is not part of an impersonated session must not present
	 * the session token of an impersonation - neither as its own session nor as
	 * a credential (the platform accepts a session id as the password of HTTP
	 * Basic authentication, as a token and as the password of the login form).
	 * It would act as the impersonated user without any of the checks of this
	 * class. The impersonation whose token it is, is ended (its token is
	 * revoked), and the request is refused. The same happens to a session of the
	 * impersonation that lost its marker, and to a request of another impersonated
	 * session ($ownRecordId: its own impersonation is not looked for).
	 *
	 * Nothing is looked up unless an impersonation is recorded whose session token
	 * may still be valid: a record that only waits for its cleanup after its token
	 * was revoked names no credential (ActiveImpersonations::namesCredential()).
	 *
	 * @param string|null $ownRecordId the record of the impersonation of the session of the request
	 * @return bool true if the request has to be refused
	 * @throws \Exception if the tokens can not be looked up
	 */
	public function endMisusedImpersonations(?string $ownRecordId = null): bool {
		$records = $this->registry->all();
		$recordOfToken = [];
		// how long the ids of the impersonated sessions are (recorded when they started)
		$lengths = [];
		foreach ($records as $id => $record) {
			if ($record !== null && (string)$id !== $ownRecordId && ActiveImpersonations::namesCredential($record)) {
				$recordOfToken[$record['token']] = (string)$id;
				if (isset($record['sid'])) {
					$lengths[$record['sid']] = true;
				}
			}
		}
		if ($recordOfToken === []) {
			return false;
		}
		$misused = false;
		$secrets = \array_unique(\array_merge(
			$this->util->getSessionSecrets(),
			$this->presentedCredentials(),
			$this->presentedParameters(\array_keys($lengths))
		));
		foreach ($secrets as $secret) {
			$token = $this->cleanup->findToken($secret);
			if ($token === null || !isset($recordOfToken[$token['id']])) {
				continue;
			}
			$id = $recordOfToken[$token['id']];
			$record = $records[$id];
			// the id alone could be the one of an unrelated, later token (a database may reuse ids)
			if ($record === null || $record['target'] !== $token['uid']) {
				continue;
			}
			$misused = true;
			$this->logger->warning(
				'The session token of the impersonation of user "{target}" by "{impersonator}" was presented by a request that is not part of the impersonated session (from {remote}): the impersonation is ended',
				[
					'app' => 'impersonate',
					'target' => $record['target'],
					'impersonator' => $record['impersonator'],
					'remote' => $this->request->getRemoteAddress(),
				]
			);
			$this->reconciler->end($id, $record, Reconciler::REASON_TOKEN_MISUSE);
		}
		if ($misused) {
			try {
				// the platform may have logged the request in with that token already
				$this->userSession->logout();
			} catch (\Throwable $e) {
				$this->logger->logException($e, ['app' => 'impersonate']);
			}
		}
		return $misused;
	}

	/**
	 * Request parameters that could be the session id of an impersonation: the
	 * login form and other operations take a credential as a parameter,
	 * whatever its name is and wherever it sits (query, form, JSON body, nested).
	 *
	 * A value is looked up if it is as long as the id of an impersonated session
	 * (the records say how long) or has the shape of a session id of this PHP.
	 * A request with more such values than a request ever needs is not looked at
	 * any further: it is refused (the lookups must not be a way to make the
	 * server work, and no value may hide behind others).
	 *
	 * Which parameters are examined: see requestParameters().
	 *
	 * @param int[] $lengths lengths of the ids of the impersonated sessions
	 * @return string[]
	 * @throws RefusedException if the request has too many candidates
	 */
	private function presentedParameters(array $lengths): array {
		$pattern = self::sessionIdPattern();
		$candidates = [];
		$parameters = $this->requestParameters();
		\array_walk_recursive($parameters, static function ($value) use (&$candidates, $pattern, $lengths): void {
			if (!\is_string($value)) {
				return;
			}
			// as it is, and without surrounding white space
			foreach (\array_unique([$value, \trim($value)]) as $candidate) {
				if (\preg_match($pattern, $candidate) === 1
					|| (\in_array(\strlen($candidate), $lengths, true) && \preg_match('/^[\x21-\x7e]+\z/', $candidate) === 1)
				) {
					$candidates[$candidate] = true;
					// the limit bounds the work, not only the lookups: nothing more is looked at
					if (\count($candidates) > self::MAX_PARAMETER_CANDIDATES) {
						throw new RefusedException('too many request values in the shape of a session id while an impersonation is active');
					}
				}
			}
		});
		return \array_map('strval', \array_keys($candidates));
	}

	/**
	 * The parameters of the request: what the platform hands to its controllers
	 * as parameters (query, form, a JSON or form encoded body).
	 *
	 * This runs for every request of every user while an impersonation is
	 * recorded, so it must not change what happens to the request. The platform
	 * is therefore not asked for the parameters (IRequest::getParams()) where
	 * the body is no set of parameters:
	 *
	 * - a PUT request with a body that is neither JSON nor form encoded: the
	 *   platform hands such a body out as a stream, once, and asking for the
	 *   parameters counts as that one time - the request would be refused here
	 *   or fail later (an upload through a public link, for example);
	 * - a request to a WebDAV entry point: its body is a file or a WebDAV
	 *   document of any size, and decoding it (a large JSON file) can take
	 *   more memory than the request may use.
	 *
	 * For those only the parameters PHP itself has parsed are examined (query
	 * and form). Credentials of such requests travel in a header or in the
	 * session, which are always examined (presentedCredentials(),
	 * Util::getSessionSecrets()).
	 *
	 * @return array<mixed>
	 */
	private function requestParameters(): array {
		$entryPoint = \strtolower(\basename((string)($_SERVER['SCRIPT_FILENAME'] ?? '')));
		if (\in_array($entryPoint, self::WEBDAV_ENTRY_POINTS, true) || $this->hasRawPutBody()) {
			return [$_GET, $_POST];
		}
		return $this->request->getParams();
	}

	/**
	 * Is this a PUT request whose body the platform does not decode into parameters?
	 *
	 * Only if nothing says otherwise: the content type is taken from every place
	 * it can come from (the platform's view of the header and both names a web
	 * server may hand it over under). If any of them names JSON or a form, the
	 * platform is asked for the parameters as before.
	 */
	private function hasRawPutBody(): bool {
		if (\strtoupper((string)$this->request->getMethod()) !== 'PUT') {
			return false;
		}
		$types = [
			$this->request->getHeader('Content-Type'),
			$_SERVER['CONTENT_TYPE'] ?? null,
			$_SERVER['HTTP_CONTENT_TYPE'] ?? null,
		];
		foreach ($types as $type) {
			$type = \is_string($type) ? \strtolower($type) : '';
			if (\strpos($type, 'application/json') !== false
				|| \strpos($type, 'application/x-www-form-urlencoded') !== false
			) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The shape of the session ids of this PHP (settings session.sid_length and
	 * session.sid_bits_per_character), or of any session id if they are unusual.
	 */
	private static function sessionIdPattern(): string {
		$length = (int)\ini_get('session.sid_length');
		$characters = [4 => '0-9a-f', 5 => '0-9a-v', 6 => '0-9a-zA-Z,-'][(int)\ini_get('session.sid_bits_per_character')] ?? null;
		if ($length < 22 || $length > 256 || $characters === null) {
			return '/^[0-9a-zA-Z,-]{22,256}\z/';
		}
		return '/^[' . $characters . ']{' . $length . '}\z/';
	}

	/**
	 * @return string[] what the request presents as a credential: the password of HTTP
	 *                  Basic authentication and the value of any other Authorization header
	 */
	private function presentedCredentials(): array {
		$secrets = [];
		$password = $_SERVER['PHP_AUTH_PW'] ?? null;
		if (\is_string($password) && $password !== '') {
			$secrets[] = $password;
		}
		$headers = [
			$this->request->getHeader('Authorization'),
			// where the web server hands the header over under another name
			$_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null,
		];
		foreach ($headers as $header) {
			if (!\is_string($header) || \trim($header) === '') {
				continue;
			}
			$parts = \preg_split('/\s+/', \trim($header), 2);
			if ($parts === false || \count($parts) !== 2) {
				continue;
			}
			[$scheme, $value] = $parts;
			if (\strtolower($scheme) === 'basic') {
				// decoded strictly and as tolerantly as a component that authenticates the request may
				// decode it (which skips characters that are not Base64): the check sees what it sees
				foreach ([\base64_decode($value, true), \base64_decode($value)] as $decoded) {
					$colon = \is_string($decoded) ? \strpos($decoded, ':') : false;
					if ($colon !== false) {
						$secrets[] = \substr((string)$decoded, $colon + 1);
					}
				}
			} else {
				$secrets[] = $value;
			}
		}
		return \array_values(\array_filter($secrets, static function (string $secret): bool {
			return $secret !== '';
		}));
	}

	/**
	 * End the impersonation (and log the session out) when the impersonator
	 * no longer exists, was disabled, lost the permission to impersonate the
	 * current user, when the impersonator's parked session was revoked, when
	 * the maximum duration was reached, when the impersonation was ended
	 * outside of this session or when the session is not bound to the session
	 * token it was started with anymore.
	 *
	 * @return bool true if the impersonation is (still) valid or there is none
	 */
	public function validate(): bool {
		$impersonatorUid = $this->util->getImpersonatorUid();
		if ($impersonatorUid === null) {
			return true;
		}
		$targetUid = $this->util->getTargetUid();
		// the impersonated user for the log: as recorded at the start, else the user of the session
		$loggedTarget = (string)$targetUid;
		$reason = null;
		if (\OC_User::isIncognitoMode()) {
			// Core hides the user of the session (e.g. an update is pending): what can be decided
			// without the users is still decided.
			if ($this->util->hasEndedElsewhere()) {
				$reason = Util::REASON_ENDED_ELSEWHERE;
			} elseif (!$this->util->isBoundToItsToken()) {
				$reason = Util::REASON_OTHER_SESSION;
			} elseif ($this->policy->hasExceededMaxDuration($this->util->getStartTime())) {
				$reason = 'the maximum duration of the impersonation was reached';
			}
		} elseif (($target = $this->userSession->getUser()) === null) {
			// what is observed, not a guess at the cause (the user may be deleted or its backend unavailable)
			$reason = 'the session has no user';
		} elseif ($targetUid !== null && $target->getUID() !== $targetUid) {
			$reason = 'the user of the session is not the impersonated user';
		} elseif ($this->util->hasEndedElsewhere()) {
			// the record of the impersonation is the authority: without it the session does not go on
			$loggedTarget = $target->getUID();
			$reason = Util::REASON_ENDED_ELSEWHERE;
		} elseif (!$this->util->isBoundToItsToken()) {
			$loggedTarget = $target->getUID();
			$reason = Util::REASON_OTHER_SESSION;
		} else {
			$loggedTarget = $target->getUID();
			$impersonator = $this->userManager->get($impersonatorUid);
			if ($impersonator === null) {
				$reason = 'the impersonator does not exist anymore';
			} elseif (!$impersonator->isEnabled()) {
				$reason = 'the impersonator has been disabled';
			} elseif ($this->policy->check($impersonator, $target) !== null) {
				$reason = 'the impersonator is not allowed to impersonate this user anymore';
			} elseif ($this->policy->hasExceededMaxDuration($this->util->getStartTime())) {
				$reason = 'the maximum duration of the impersonation was reached';
			} elseif (!$this->util->touchParkedToken()) {
				$reason = "the impersonator's own session was revoked or has expired";
			}
		}
		if ($reason === null) {
			return true;
		}

		$this->logger->warning(
			'Ending impersonation of user "{target}" by "{impersonator}": {reason}',
			[
				'app' => 'impersonate',
				'target' => $loggedTarget,
				'impersonator' => $impersonatorUid,
				'reason' => $reason,
			]
		);
		// dispatches the end event; the logout listener finds no impersonation anymore
		$this->util->endImpersonation($reason);
		$this->userSession->logout();
		return false;
	}

	/**
	 * Requests that would give the impersonator lasting access to the account
	 * (app passwords, URL signing key, OAuth2 grants, and what the operator
	 * added to the app config "forbidden_prefixes") are refused. So is a request
	 * whose path can not be determined.
	 */
	public function isForbiddenRequest(): bool {
		if (!$this->util->isImpersonating()) {
			return false;
		}
		$paths = self::candidatePaths($this->request);
		if ($paths === null) {
			return true;
		}
		$method = \strtoupper($this->request->getMethod());
		$prefixes = \array_merge(self::FORBIDDEN_PREFIXES, $this->policy->getExtraForbiddenPrefixes());
		foreach ($paths as $requested) {
			foreach (self::comparablePaths($requested) as $path) {
				if ($path === self::LOGOUT_PATH) {
					continue;
				}
				foreach (self::FORBIDDEN as [$forbiddenMethod, $forbiddenPath]) {
					if ($path === $forbiddenPath && ($forbiddenMethod === '*' || $forbiddenMethod === $method)) {
						return true;
					}
				}
				foreach ($prefixes as $prefix) {
					if (\strpos($path . '/', $prefix) === 0) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/**
	 * The request path as the router matches it: raw path info with repeated
	 * slashes collapsed, URL decoded, without trailing slash. An empty string if
	 * it can not be determined.
	 */
	public static function normalizedPath(IRequest $request): string {
		$paths = self::candidatePaths($request);
		return $paths[0] ?? '';
	}

	/**
	 * @return string[]|null normalized variants of the request path (raw and decoded path
	 *                       info), null if the path can not be determined
	 */
	private static function candidatePaths(IRequest $request): ?array {
		$paths = [];
		foreach (['getRawPathInfo', 'getPathInfo'] as $getter) {
			try {
				$path = $request->$getter();
			} catch (\Throwable $e) {
				return null;
			}
			if ($path === false || $path === null) {
				// no path info: the front page
				$path = '';
			}
			if (!\is_string($path)) {
				return null;
			}
			$path = \rawurldecode((string)\preg_replace('%/{2,}%', '/', $path));
			$path = (string)\preg_replace('%/{2,}%', '/', $path);
			$path = \rtrim($path, '/');
			$paths[] = $path === '' ? '/' : $path;
			// and with "." and ".." resolved: the compared form must not depend on whether a
			// component behind the guard resolves them
			$paths[] = self::withoutDotSegments($path);
		}
		return \array_values(\array_unique($paths));
	}

	private static function withoutDotSegments(string $path): string {
		$segments = [];
		foreach (\explode('/', $path) as $segment) {
			if ($segment === '..') {
				\array_pop($segments);
			} elseif ($segment !== '' && $segment !== '.') {
				$segments[] = $segment;
			}
		}
		return '/' . \implode('/', $segments);
	}

	/**
	 * The request path as it is written to the log: URL decoded, so control characters and line
	 * separators (that would forge log lines) are replaced, and its length is limited.
	 */
	private static function loggablePath(IRequest $request): string {
		$path = \mb_scrub(self::normalizedPath($request), 'UTF-8');
		$path = (string)\preg_replace('/[\x{00}-\x{1F}\x{7F}-\x{9F}\x{2028}\x{2029}]/u', '?', $path);
		return \strlen($path) > self::LOGGED_PATH_LENGTH ? \mb_strcut($path, 0, self::LOGGED_PATH_LENGTH, 'UTF-8') . '...' : $path;
	}

	/**
	 * The forms of a path the deny-list is compared with: lower-case (routes are
	 * matched case-sensitively, so this only widens the list), as requested and
	 * without leading entry point segments.
	 *
	 * @return string[]
	 */
	private static function comparablePaths(string $path): array {
		$path = \mb_strtolower($path);
		$paths = [$path];
		$segments = \explode('/', \ltrim($path, '/'));
		// Leading segments that only select an entry point or an API version are dropped,
		// so that a blocked operation is also recognized under another entry point.
		while (\count($segments) > 1 && \in_array($segments[0], Policy::ENTRY_POINT_SEGMENTS, true)) {
			\array_shift($segments);
			$paths[] = '/' . \implode('/', $segments);
		}
		return $paths;
	}

	private function logRefusal(): void {
		try {
			$target = $this->userSession->getUser();
			$this->logger->warning(
				'Refused {method} {path} for user "{target}" while "{impersonator}" impersonates them',
				[
					'app' => 'impersonate',
					'target' => $target !== null ? $target->getUID() : (string)$this->util->getTargetUid(),
					'impersonator' => $this->util->getImpersonatorUid(),
					'method' => $this->request->getMethod(),
					'path' => self::loggablePath($this->request),
				]
			);
		} catch (\Throwable $e) {
			// the request is refused whether or not that could be logged
		}
	}

	/**
	 * Answer the request with the HTTP status of the refusal and stop processing it.
	 *
	 * @codeCoverageIgnore
	 */
	private static function refuse(int $status): void {
		self::discardOutputBuffers();
		\http_response_code(self::HTTP_STATUS[$status] ?? 503);
		\header('Content-Type: application/json; charset=utf-8');
		\header('Cache-Control: no-store');
		\header('X-Content-Type-Options: nosniff');
		if ($status === self::UNVERIFIED) {
			\header('Retry-After: 5');
		}
		echo \json_encode(['message' => self::MESSAGES[$status] ?? 'Refused']);
		exit();
	}

	/**
	 * Drop what was written to the output buffers before the refusal. A buffer that can not be
	 * removed (opened without the flag that allows it, or the one of zlib.output_compression once
	 * output went through it) stays and the answer goes through it: the loop ends there instead of
	 * running until the time limit of the request.
	 *
	 * @param callable|null $level for the tests: what ob_get_level() says
	 * @param callable|null $discard for the tests: ob_end_clean(), true if a buffer was removed
	 */
	public static function discardOutputBuffers(?callable $level = null, ?callable $discard = null): void {
		$level = $level ?? static function (): int {
			return \ob_get_level();
		};
		$discard = $discard ?? static function (): bool {
			return @\ob_end_clean();
		};
		while (($before = $level()) > 0) {
			if (!$discard() || $level() >= $before) {
				break;
			}
		}
	}
}
