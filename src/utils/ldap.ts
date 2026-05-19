import { Client } from "ldapts";
import type { LdapConfig, StorageRule } from "../config/schema.ts";

export async function checkLdapAccess(
  pubkey: string,
  config: LdapConfig,
  ruleLdap: NonNullable<StorageRule["ldap"]>,
): Promise<boolean> {
  if (!config.enabled || !config.url) return false;

  const client = new Client({ url: config.url });
  try {
    if (config.bindDN && config.password) {
      await client.bind(config.bindDN, config.password);
    }

    const baseDN = ruleLdap.searchDN || config.searchDN;
    const filter = ruleLdap.filter.replace("{pubkey}", pubkey);

    const { searchEntries } = await client.search(baseDN, {
      filter,
      attributes: ["dn"],
      sizeLimit: 1,
    });

    return searchEntries.length > 0;
  } catch (err) {
    console.warn(`[ldap] Search failed for pubkey ${pubkey}:`, err);
    return false;
  } finally {
    try {
      await client.unbind();
    } catch (_) {
      // Ignore unbind errors
    }
  }
}
