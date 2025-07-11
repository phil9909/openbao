// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"strings"

	"github.com/openbao/openbao/helper/namespace"
)

func (c *Core) Invalidate(key string) {
	ctx := c.activeContext

	namespacedKey := key
	ns := namespace.RootNamespace
	namespaceUUID := namespace.RootNamespaceUUID

	if keySuffix, ok := strings.CutPrefix(key, namespaceBarrierPrefix); ok {
		namespaceUUID, namespacedKey, _ = strings.Cut(keySuffix, "/")
		var err error
		ns, err = c.namespaceStore.GetNamespace(ctx, namespaceUUID)

		if err != nil {
			c.logger.Error("error while invalidating cache: could not find namespace", "key", key, "error", err.Error())
			// We can't find the namespace, but let's still try to invalidate the cache
		} else {
			ctx = namespace.ContextWithNamespace(ctx, ns)
		}
	}

	switch {
	// TODO:
	// 1. A plugin backend
	// 3. Token store
	// 4. Quota manager
	// 5. Audit broker
	// 6. Expiration manager
	// 8. Identity store

	case strings.HasPrefix(namespacedKey, namespaceStoreSubPath):
		c.namespaceStore.invalidate(ctx, "")

	case strings.HasPrefix(namespacedKey, "sys/policy/"):
		policyType := PolicyTypeACL // for now it is safe to assume type is ACL
		c.policyStore.invalidate(ctx, strings.TrimPrefix(namespacedKey, "sys/policy/"), policyType)

	case strings.HasPrefix(namespacedKey, coreLocalMountConfigPath+"/") || strings.HasPrefix(namespacedKey, coreMountConfigPath+"/"):
		// TODO(phil9909): implement this

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+loginMFAConfigPrefix):
		err := c.loginMFABackend.loadMFAMethodConfigs(ctx, ns)
		if err != nil {
			c.logger.Error("error while invalidating cache: (re)loading mfa methods failed", "key", key, "error", err.Error())
		}
		// TODO(phil9909): deletions are not handled (I think)

	case strings.HasPrefix(namespacedKey, systemBarrierPrefix+mfaLoginEnforcementPrefix):
		eConfigs, err := c.loginMFABackend.loadMFAEnforcementConfigs(ctx, ns)
		if err != nil {
			c.logger.Error("error while invalidating cache: (re)loading mfa enforcments failed", "key", key, "error", err.Error())
		}
		for _, conf := range eConfigs {
			if err := c.loginMFABackend.loginMFAMethodExistenceCheck(conf); err != nil {
				c.loginMFABackend.mfaLogger.Error("failed to find all MFA methods that exist in MFA enforcement configs", "configID", conf.ID, "namespaceID", conf.NamespaceID, "error", err.Error())
			}
		}
		// TODO(phil9909): deletions are not handled (I think)

	default:
		c.logger.Warn("no idea how to invalidate cache. Maybe it's not cached and this is fine, maybe not", "key", key)

	}

}
