import { createHmac } from "crypto";

export const DELETE_ACCOUNT_DELETED_SCOPES = [
  "storage.hushh_ai_media",
  "storage.signed_nda_pdfs",
  "database.financial_data",
  "database.onboarding_and_profile_data",
  "database.identity_and_privacy_data",
  "database.public_user_branch",
  "database.ai_and_agent_data",
  "database.legacy_investor_agent_data",
  "auth.account",
];

export const DELETE_ACCOUNT_RETAINED_SCOPES = ["audit.payment_minimum"];

const DEFAULT_DELETE_ACCOUNT_RESULT_DETAILS = {
  archivedPaymentAuditRows: 0,
  hushhAiMediaObjectsDeleted: 0,
  ndaAssetObjectsDeleted: 0,
};

const AUDIT_KEY_PREFIX = "deleted_account_payment_audit:";
const DELETE_ACCOUNT_HASH_NAMESPACE = "delete-account-payment-audit";
const SIGNED_NDA_MARKER = "/storage/v1/object/public/assets/";
const MISSING_RELATION_CODES = new Set(["42P01", "PGRST202", "PGRST205"]);

const buildDeleteAccountSuccessPayload = (details = {}) => ({
  success: true,
  deletedScopes: DELETE_ACCOUNT_DELETED_SCOPES,
  retainedScopes: DELETE_ACCOUNT_RETAINED_SCOPES,
  details: {
    ...DEFAULT_DELETE_ACCOUNT_RESULT_DETAILS,
    ...details,
  },
});

const buildErrorResult = (status, error, details, code) => ({
  status,
  body: {
    success: false,
    error,
    details,
    code,
  },
});

const toArray = (value) => (Array.isArray(value) ? value : []);

const uniqueValues = (values) => [
  ...new Set(
    toArray(values).filter(
      (value) => value !== null && value !== undefined && `${value}`.trim().length > 0
    )
  ),
];

const chunkArray = (values, size = 100) => {
  const items = uniqueValues(values);
  const chunks = [];

  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }

  return chunks;
};

const isRelationMissingError = (error) => {
  if (!error) return false;

  if (typeof error.code === "string" && MISSING_RELATION_CODES.has(error.code)) {
    return true;
  }

  const message = `${error.message || ""}`.toLowerCase();
  return (
    message.includes("relation") ||
    message.includes("schema cache") ||
    message.includes("could not find the table")
  );
};

const getErrorMessage = (error) => error?.message || error?.code || "Unknown error";

const extractBearerToken = (authHeader) => {
  if (!authHeader) return null;

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
};

const resolveUserValidationMessage = (error) => {
  if (error?.status === 401 || `${error?.message || ""}`.includes("expired")) {
    return "Your session has expired. Please log out, log back in, and try again.";
  }

  return getErrorMessage(error) || "Invalid or expired token";
};

const dedupeDeleteAccountPaths = (values) => uniqueValues(values.map((value) => value?.trim?.()));

const buildSignedNdaAssetPathFromUrl = (urlValue) => {
  if (!urlValue) return null;

  try {
    const url = new URL(urlValue);
    const markerIndex = url.pathname.indexOf(SIGNED_NDA_MARKER);

    if (markerIndex === -1) {
      return null;
    }

    const assetPath = decodeURIComponent(
      url.pathname.slice(markerIndex + SIGNED_NDA_MARKER.length)
    );

    if (assetPath.includes('..')) {
      return null;
    }

    return assetPath.startsWith("signed-ndas/") ? assetPath : null;
  } catch {
    return null;
  }
};

const createServiceHeaders = (serviceRoleKey, extraHeaders = {}) => ({
  apikey: serviceRoleKey,
  Authorization: `Bearer ${serviceRoleKey}`,
  ...extraHeaders,
});

const createUserHeaders = (serviceRoleKey, userJwt, extraHeaders = {}) => ({
  apikey: serviceRoleKey,
  Authorization: `Bearer ${userJwt}`,
  ...extraHeaders,
});

const formatFilterValue = (value) => {
  const text = `${value}`;
  if (/^[A-Za-z0-9._:-]+$/.test(text)) {
    return text;
  }

  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
};

const buildRestUrl = (supabaseUrl, path, query = {}) => {
  const url = new URL(path, supabaseUrl);

  for (const [key, value] of Object.entries(query)) {
    if (value === null || value === undefined || value === "") continue;
    url.searchParams.set(key, value);
  }

  return url.toString();
};

async function parseSupabaseResponse(response) {
  const text = await response.text();
  let payload = null;

  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (response.ok) {
    return {
      data: payload,
      error: null,
    };
  }

  const errorBody =
    payload && typeof payload === "object"
      ? payload
      : {
          message:
            typeof payload === "string" && payload.length > 0
              ? payload
              : response.statusText || "Supabase request failed",
        };

  return {
    data: null,
    error: {
      status: response.status,
      code: errorBody.code,
      message: errorBody.message || errorBody.error || response.statusText,
      details: errorBody.details,
      hint: errorBody.hint,
    },
  };
}

function createRestAdminClient(supabaseUrl, serviceRoleKey) {
  async function requestJson(method, path, { query, body, headers } = {}) {
    const response = await fetch(buildRestUrl(supabaseUrl, path, query), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    return parseSupabaseResponse(response);
  }

  return {
    auth: {
      async getUser(jwt) {
        const { data, error } = await requestJson("GET", "/auth/v1/user", {
          headers: createUserHeaders(serviceRoleKey, jwt),
        });

        return {
          data: { user: data },
          error,
        };
      },
      admin: {
        async deleteUser(userId) {
          return requestJson("DELETE", `/auth/v1/admin/users/${userId}`, {
            headers: createServiceHeaders(serviceRoleKey),
          });
        },
      },
    },
    from(table) {
      const encodedTable = encodeURIComponent(table);

      return {
        select(columns) {
          return {
            eq(column, value) {
              return requestJson("GET", `/rest/v1/${encodedTable}`, {
                query: {
                  select: columns,
                  [column]: `eq.${formatFilterValue(value)}`,
                },
                headers: createServiceHeaders(serviceRoleKey),
              });
            },
            in(column, values) {
              return requestJson("GET", `/rest/v1/${encodedTable}`, {
                query: {
                  select: columns,
                  [column]: `in.(${uniqueValues(values).map(formatFilterValue).join(",")})`,
                },
                headers: createServiceHeaders(serviceRoleKey),
              });
            },
          };
        },
        delete() {
          return {
            eq(column, value) {
              return requestJson("DELETE", `/rest/v1/${encodedTable}`, {
                query: {
                  [column]: `eq.${formatFilterValue(value)}`,
                },
                headers: createServiceHeaders(serviceRoleKey, {
                  Prefer: "return=minimal",
                }),
              });
            },
            in(column, values) {
              return requestJson("DELETE", `/rest/v1/${encodedTable}`, {
                query: {
                  [column]: `in.(${uniqueValues(values).map(formatFilterValue).join(",")})`,
                },
                headers: createServiceHeaders(serviceRoleKey, {
                  Prefer: "return=minimal",
                }),
              });
            },
          };
        },
        upsert(payload, options = {}) {
          return requestJson("POST", `/rest/v1/${encodedTable}`, {
            query: {
              on_conflict: options.onConflict,
            },
            body: payload,
            headers: createServiceHeaders(serviceRoleKey, {
              "Content-Type": "application/json",
              Prefer: "resolution=merge-duplicates,return=minimal",
            }),
          });
        },
      };
    },
    storage: {
      from(bucket) {
        const encodedBucket = encodeURIComponent(bucket);

        return {
          list(path = "", options = {}) {
            return requestJson("POST", `/storage/v1/object/list/${encodedBucket}`, {
              body: {
                prefix: path,
                limit: options.limit,
                offset: options.offset,
                sortBy: options.sortBy,
              },
              headers: createServiceHeaders(serviceRoleKey, {
                "Content-Type": "application/json",
              }),
            });
          },
          remove(paths) {
            return requestJson("DELETE", `/storage/v1/object/${encodedBucket}`, {
              body: {
                prefixes: uniqueValues(paths),
              },
              headers: createServiceHeaders(serviceRoleKey, {
                "Content-Type": "application/json",
              }),
            });
          },
        };
      },
    },
  };
}

const mapColumnValues = (rows, column) =>
  uniqueValues(
    toArray(rows).map((row) =>
      row && typeof row === "object" ? row[column] : null
    )
  );

async function runSelect(queryPromise, description) {
  const { data, error } = await queryPromise;

  if (error) {
    if (isRelationMissingError(error)) {
      return [];
    }

    throw new Error(`${description}: ${getErrorMessage(error)}`);
  }

  return toArray(data);
}

async function runMutation(queryPromise, description) {
  const { error } = await queryPromise;

  if (error && !isRelationMissingError(error)) {
    throw new Error(`${description}: ${getErrorMessage(error)}`);
  }
}

async function selectEq(adminClient, table, columns, column, value) {
  if (value === null || value === undefined || `${value}`.trim().length === 0) {
    return [];
  }

  return runSelect(
    adminClient.from(table).select(columns).eq(column, value),
    `Failed to query ${table}`
  );
}

async function selectIn(adminClient, table, columns, column, values) {
  const rows = [];

  for (const chunk of chunkArray(values)) {
    const result = await runSelect(
      adminClient.from(table).select(columns).in(column, chunk),
      `Failed to query ${table}`
    );
    rows.push(...result);
  }

  return rows;
}

async function deleteEq(adminClient, table, column, value) {
  if (value === null || value === undefined || `${value}`.trim().length === 0) {
    return;
  }

  await runMutation(
    adminClient.from(table).delete().eq(column, value),
    `Failed to delete ${table}`
  );
}

async function deleteIn(adminClient, table, column, values) {
  for (const chunk of chunkArray(values)) {
    await runMutation(
      adminClient.from(table).delete().in(column, chunk),
      `Failed to delete ${table}`
    );
  }
}

async function listStorageFiles(adminClient, bucket, prefix) {
  const files = [];

  async function walk(path) {
    const { data, error } = await adminClient.storage.from(bucket).list(path, {
      limit: 1000,
      offset: 0,
      sortBy: { column: "name", order: "asc" },
    });

    if (error) {
      const message = `${getErrorMessage(error)}`.toLowerCase();
      if (message.includes("not found") || message.includes("no such bucket")) {
        return;
      }

      throw new Error(`Failed to list storage objects in ${bucket}: ${getErrorMessage(error)}`);
    }

    for (const entry of toArray(data)) {
      if (!entry?.name) continue;

      const childPath = path ? `${path}/${entry.name}` : entry.name;
      if (entry.id || entry.metadata) {
        files.push(childPath);
        continue;
      }

      await walk(childPath);
    }
  }

  await walk(prefix);
  return files;
}

async function deleteBucketPaths(adminClient, bucket, paths) {
  const filePaths = dedupeDeleteAccountPaths(paths);

  if (filePaths.length === 0) {
    return 0;
  }

  for (const chunk of chunkArray(filePaths, 100)) {
    const { error } = await adminClient.storage.from(bucket).remove(chunk);
    if (error) {
      throw new Error(
        `Failed to delete storage objects from ${bucket}: ${getErrorMessage(error)}`
      );
    }
  }

  return filePaths.length;
}

async function deleteHushhAiMedia(adminClient, userId) {
  const files = await listStorageFiles(adminClient, "hushh-ai-media", userId);
  return deleteBucketPaths(adminClient, "hushh-ai-media", files);
}

function buildFormerUserIdHash(userId, auditSecret) {
  return createHmac("sha256", `${auditSecret}:${DELETE_ACCOUNT_HASH_NAMESPACE}`)
    .update(userId)
    .digest("hex");
}

async function archivePaymentAuditRows(adminClient, paymentRows, userId, auditSecret) {
  const rows = toArray(paymentRows);
  if (rows.length === 0) {
    return 0;
  }

  const formerUserIdHash = buildFormerUserIdHash(userId, auditSecret);
  const deletedAt = new Date().toISOString();
  const payload = rows.map((row) => ({
    key: `${AUDIT_KEY_PREFIX}${row.id}`,
    value: {
      type: "deleted_account_payment_audit",
      formerUserIdHash,
      paymentMethod: row.payment_method || "stripe",
      paymentStatus: row.payment_status || "pending",
      amountCents: row.amount_cents ?? null,
      stripeSessionId: row.stripe_session_id ?? null,
      stripePaymentIntent: row.stripe_payment_intent ?? null,
      originalPaymentCreatedAt: row.created_at ?? deletedAt,
      deletedAt,
    },
  }));

  const { error } = await adminClient
    .from("app_config")
    .upsert(payload, { onConflict: "key" });

  if (error) {
    throw new Error(`Failed to archive payment audit rows: ${getErrorMessage(error)}`);
  }

  return rows.length;
}

async function collectDeleteContext(adminClient, userId) {
  const userIdText = String(userId);

  const [profileRows, investorAgentRows, leadRows, hushhAiUserRows, intelligenceUserRows, ndaSignatureRows, onboardingRows, plaidItemRows, kycProfileRows, financialRows, ceoPaymentRows, consumerConversationRows] =
    await Promise.all([
      selectEq(adminClient, "investor_profiles", "slug", "user_id", userId),
      selectEq(adminClient, "investor_agents", "slug", "user_id", userId),
      selectEq(adminClient, "lead_requests", "id", "user_id", userId),
      selectEq(adminClient, "hushh_ai_users", "id", "supabase_user_id", userId),
      selectEq(adminClient, "intelligence_users", "id", "supabase_user_id", userId),
      selectEq(adminClient, "nda_signatures", "pdf_url", "user_id", userId),
      selectEq(adminClient, "onboarding_data", "nda_pdf_url", "user_id", userId),
      selectEq(adminClient, "plaid_items", "plaid_item_id", "user_id", userIdText),
      selectEq(adminClient, "kyc_profiles", "plaid_item_id", "user_id", userIdText),
      selectEq(adminClient, "user_financial_data", "plaid_item_id", "user_id", userId),
      selectEq(
        adminClient,
        "ceo_meeting_payments",
        "id,payment_method,payment_status,amount_cents,stripe_session_id,stripe_payment_intent,created_at",
        "user_id",
        userId
      ),
      selectEq(adminClient, "conversations", "id", "consumer_id", userId),
    ]);

  const leadIds = mapColumnValues(leadRows, "id");
  const conversationRowsByLeadId = await selectIn(
    adminClient,
    "conversations",
    "id",
    "lead_id",
    leadIds
  );
  const conversationIds = uniqueValues([
    ...mapColumnValues(consumerConversationRows, "id"),
    ...mapColumnValues(conversationRowsByLeadId, "id"),
  ]);

  const hushhAiUserIds = mapColumnValues(hushhAiUserRows, "id");
  const hushhAiChatRows = await selectIn(
    adminClient,
    "hushh_ai_chats",
    "id",
    "user_id",
    hushhAiUserIds
  );

  const intelligenceUserIds = mapColumnValues(intelligenceUserRows, "id");
  const intelligenceConversationRows = await selectIn(
    adminClient,
    "intelligence_conversations",
    "id",
    "user_id",
    intelligenceUserIds
  );

  const plaidItemIds = uniqueValues([
    ...mapColumnValues(plaidItemRows, "plaid_item_id"),
    ...mapColumnValues(kycProfileRows, "plaid_item_id"),
    ...mapColumnValues(financialRows, "plaid_item_id"),
  ]);
  const plaidAccountRows = await selectIn(
    adminClient,
    "plaid_accounts",
    "plaid_account_id",
    "plaid_item_id",
    plaidItemIds
  );

  return {
    ceoPaymentRows,
    conversationIds,
    hushhAiChatIds: mapColumnValues(hushhAiChatRows, "id"),
    hushhAiUserIds,
    intelligenceConversationIds: mapColumnValues(intelligenceConversationRows, "id"),
    intelligenceUserIds,
    leadIds,
    ndaAssetPaths: dedupeDeleteAccountPaths(
      [...mapColumnValues(ndaSignatureRows, "pdf_url"), ...mapColumnValues(onboardingRows, "nda_pdf_url")].map(
        buildSignedNdaAssetPathFromUrl
      )
    ),
    plaidAccountIds: mapColumnValues(plaidAccountRows, "plaid_account_id"),
    plaidItemIds,
    profileSlugs: uniqueValues([
      ...mapColumnValues(profileRows, "slug"),
      ...mapColumnValues(investorAgentRows, "slug"),
    ]),
  };
}

async function purgeUserData(adminClient, userId, context) {
  const userIdText = String(userId);

  await deleteIn(adminClient, "messages", "conversation_id", context.conversationIds);
  await deleteEq(adminClient, "messages", "sender_id", userId);
  await deleteIn(adminClient, "lead_events", "lead_id", context.leadIds);
  await deleteIn(adminClient, "conversations", "id", context.conversationIds);
  await deleteEq(adminClient, "lead_requests", "user_id", userId);

  await deleteEq(adminClient, "analytics_events", "user_id", userId);
  await deleteEq(adminClient, "blocked_agents", "user_id", userId);
  await deleteEq(adminClient, "consumer_profiles", "user_id", userId);
  await deleteEq(adminClient, "delete_requests", "user_id", userId);
  await deleteEq(adminClient, "devices", "user_id", userId);
  await deleteEq(adminClient, "notifications", "user_id", userId);
  await deleteEq(adminClient, "swipe_actions", "user_id", userId);
  await deleteEq(adminClient, "agent_reviews", "user_id", userId);

  await deleteEq(adminClient, "consents", "user_id", userId);
  await deleteEq(adminClient, "community_registrations", "user_id", userId);
  await deleteEq(adminClient, "kyc_consent_tokens", "user_id", userId);
  await deleteEq(adminClient, "identity_verifications", "user_id", userId);
  await deleteEq(adminClient, "user_product_usage", "user_id", userId);
  await deleteEq(adminClient, "user_enriched_profiles", "user_id", userId);
  await deleteEq(adminClient, "user_agent_selections", "user_id", userId);
  await deleteEq(adminClient, "nda_signatures", "user_id", userId);
  await deleteEq(adminClient, "kyc_profiles", "user_id", userIdText);

  await deleteIn(
    adminClient,
    "plaid_transactions",
    "plaid_account_id",
    context.plaidAccountIds
  );
  await deleteIn(adminClient, "plaid_sync_cursors", "plaid_item_id", context.plaidItemIds);
  await deleteIn(adminClient, "plaid_accounts", "plaid_item_id", context.plaidItemIds);
  await deleteEq(adminClient, "plaid_items", "user_id", userIdText);
  await deleteEq(adminClient, "user_financial_data", "user_id", userId);

  await deleteIn(adminClient, "hushh_ai_messages", "chat_id", context.hushhAiChatIds);
  await deleteIn(adminClient, "hushh_ai_chats", "user_id", context.hushhAiUserIds);
  await deleteIn(adminClient, "hushh_ai_media_limits", "user_id", context.hushhAiUserIds);
  await deleteEq(adminClient, "hushh_ai_media_limits", "user_id", userIdText);
  await deleteEq(adminClient, "hushh_ai_users", "supabase_user_id", userId);
  await deleteEq(adminClient, "hushh_ai_rate_limits", "user_id", userIdText);

  await deleteIn(
    adminClient,
    "intelligence_messages",
    "conversation_id",
    context.intelligenceConversationIds
  );
  await deleteIn(
    adminClient,
    "intelligence_conversations",
    "user_id",
    context.intelligenceUserIds
  );
  await deleteIn(
    adminClient,
    "intelligence_media_limits",
    "user_id",
    context.intelligenceUserIds
  );
  await deleteEq(adminClient, "intelligence_users", "supabase_user_id", userId);

  await deleteEq(adminClient, "agent_tasks", "user_id", userId);
  await deleteEq(adminClient, "agent_messages", "user_id", userId);
  await deleteEq(adminClient, "investor_agents", "user_id", userId);
  await deleteIn(adminClient, "investor_inquiries", "slug", context.profileSlugs);
  await deleteIn(adminClient, "public_chat_messages", "slug", context.profileSlugs);

  await deleteEq(adminClient, "onboarding_data", "user_id", userId);
  await deleteEq(adminClient, "investor_profiles", "user_id", userId);
  await deleteEq(adminClient, "ceo_meeting_payments", "user_id", userId);
  await deleteEq(adminClient, "kyc_attestations", "user_id", userId);
  await deleteEq(adminClient, "users", "id", userId);
}

export function createDeleteAccountAdminClientFromEnv() {
  const supabaseUrl = process.env.SUPABASE_URL?.trim();
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();

  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error("Supabase server environment variables are missing");
  }

  return {
    adminClient: createRestAdminClient(supabaseUrl, serviceRoleKey),
    auditSecret: serviceRoleKey,
  };
}

export async function executeDeleteAccount({
  adminClient,
  authHeader,
  auditSecret,
}) {
  if (!authHeader) {
    return buildErrorResult(401, "Missing authorization header");
  }

  const jwt = extractBearerToken(authHeader);
  if (!jwt) {
    return buildErrorResult(
      401,
      "Invalid authorization header format. Expected: Bearer <token>"
    );
  }

  const {
    data: { user },
    error: userError,
  } = await adminClient.auth.getUser(jwt);

  if (userError || !user) {
    return buildErrorResult(
      401,
      resolveUserValidationMessage(userError),
      getErrorMessage(userError) || "Token validation failed",
      userError?.status || 401
    );
  }

  try {
    const context = await collectDeleteContext(adminClient, user.id);
    const hushhAiMediaObjectsDeleted = await deleteHushhAiMedia(adminClient, user.id);
    const ndaAssetObjectsDeleted = await deleteBucketPaths(
      adminClient,
      "assets",
      context.ndaAssetPaths
    );
    const archivedPaymentAuditRows = await archivePaymentAuditRows(
      adminClient,
      context.ceoPaymentRows,
      user.id,
      auditSecret
    );

    await purgeUserData(adminClient, user.id, context);

    const { error: deleteAuthError } = await adminClient.auth.admin.deleteUser(user.id);
    if (deleteAuthError) {
      return buildErrorResult(
        500,
        "Failed to delete user account",
        getErrorMessage(deleteAuthError)
      );
    }

    return {
      status: 200,
      body: buildDeleteAccountSuccessPayload({
        archivedPaymentAuditRows,
        hushhAiMediaObjectsDeleted,
        ndaAssetObjectsDeleted,
      }),
    };
  } catch (error) {
    return buildErrorResult(
      500,
      "Failed to delete user account",
      error instanceof Error ? error.message : String(error)
    );
  }
}

export const __testing = {
  buildSignedNdaAssetPathFromUrl,
  buildFormerUserIdHash,
};
