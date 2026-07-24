const baseUrl = "http://localhost:8080";
const realmName = "verana-playground";
const identityProviderAlias = "verana-wallet";

interface TokenResponse {
  access_token?: string;
}

interface ClientRepresentation {
  id?: string;
  clientId?: string;
  protocol?: string;
  publicClient?: boolean;
  standardFlowEnabled?: boolean;
  implicitFlowEnabled?: boolean;
  directAccessGrantsEnabled?: boolean;
  redirectUris?: string[];
  webOrigins?: string[];
  attributes?: Record<string, string>;
}

interface IdentityProviderRepresentation {
  alias?: string;
  providerId?: string;
  enabled?: boolean;
  trustEmail?: boolean;
  storeToken?: boolean;
  firstBrokerLoginFlowAlias?: string;
  config?: Record<string, string>;
}

interface MapperRepresentation {
  name?: string;
  identityProviderMapper?: string;
  config?: Record<string, string>;
}

interface ProtocolMapperRepresentation {
  name?: string;
  protocolMapper?: string;
  config?: Record<string, string>;
}

interface AuthenticationFlowRepresentation {
  alias?: string;
  builtIn?: boolean;
  topLevel?: boolean;
}

interface AuthenticationExecutionRepresentation {
  providerId?: string;
  requirement?: string;
}

interface GroupRepresentation {
  id?: string;
  name?: string;
  path?: string;
}

interface RealmRepresentation {
  realm?: string;
  enabled?: boolean;
  sslRequired?: string;
  registrationAllowed?: boolean;
  resetPasswordAllowed?: boolean;
}

interface RoleRepresentation {
  name?: string;
}

function requireCondition(
  condition: unknown,
  message: string,
): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const requestJson = async <T>(
  path: string,
  accessToken: string,
): Promise<T> => {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    throw new Error(`Keycloak admin request failed with ${response.status}`);
  }

  return (await response.json()) as T;
};

const getAdminToken = async (): Promise<string> => {
  const response = await fetch(
    `${baseUrl}/realms/master/protocol/openid-connect/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "password",
        client_id: "admin-cli",
        username: "admin",
        password: "local-development-only",
      }),
    },
  );

  if (!response.ok) {
    throw new Error(
      `Keycloak admin authentication failed with ${response.status}`,
    );
  }

  const tokenResponse = (await response.json()) as TokenResponse;
  requireCondition(
    typeof tokenResponse.access_token === "string",
    "Keycloak admin authentication returned no access token",
  );
  return tokenResponse.access_token;
};

const getMapper = (
  mappers: MapperRepresentation[],
  name: string,
): MapperRepresentation => {
  const mapper = mappers.find((candidate) => candidate.name === name);
  requireCondition(mapper, `Missing identity-provider mapper: ${name}`);
  return mapper;
};

const getProtocolMapper = (
  mappers: ProtocolMapperRepresentation[],
  name: string,
): ProtocolMapperRepresentation => {
  const mapper = mappers.find((candidate) => candidate.name === name);
  requireCondition(mapper, `Missing client protocol mapper: ${name}`);
  return mapper;
};

const verify = async (): Promise<void> => {
  const accessToken = await getAdminToken();
  const realm = await requestJson<RealmRepresentation>(
    `/admin/realms/${realmName}`,
    accessToken,
  );
  requireCondition(
    realm.realm === realmName &&
      realm.enabled === true &&
      realm.sslRequired === "none" &&
      realm.registrationAllowed === false &&
      realm.resetPasswordAllowed === false,
    "Disposable realm security settings are invalid",
  );
  console.log("PASS realm: verana-playground");

  const clients = await requestJson<ClientRepresentation[]>(
    `/admin/realms/${realmName}/clients?clientId=playground-app`,
    accessToken,
  );
  const client = clients.find(
    (candidate) => candidate.clientId === "playground-app",
  );
  requireCondition(client?.id, "Missing playground-app client");
  requireCondition(
    client.publicClient === false &&
      client.protocol === "openid-connect" &&
      client.standardFlowEnabled === true &&
      client.implicitFlowEnabled === false &&
      client.directAccessGrantsEnabled === false &&
      client.redirectUris?.length === 1 &&
      client.redirectUris[0] === "http://localhost:3000/callback" &&
      client.webOrigins?.length === 1 &&
      client.webOrigins[0] === "http://localhost:3000" &&
      client.attributes?.["pkce.code.challenge.method"] === "S256",
    "playground-app does not enforce Authorization Code with S256",
  );
  console.log("PASS client: playground-app Authorization Code with S256");

  const identityProvider = await requestJson<IdentityProviderRepresentation>(
    `/admin/realms/${realmName}/identity-provider/instances/${identityProviderAlias}`,
    accessToken,
  );
  requireCondition(
    identityProvider.alias === identityProviderAlias &&
      identityProvider.providerId === "oidc" &&
      identityProvider.enabled === true &&
      identityProvider.trustEmail === false &&
      identityProvider.storeToken === false &&
      identityProvider.firstBrokerLoginFlowAlias ===
        "verana first broker login",
    "Missing Verana Wallet identity provider or first-login flow",
  );
  requireCondition(
    identityProvider.config?.authorizationUrl ===
      "http://localhost:3001/auth" &&
      identityProvider.config.tokenUrl ===
        "http://host.docker.internal:3001/token" &&
      identityProvider.config.issuer === "http://localhost:3001" &&
      identityProvider.config.clientId === "keycloak-playground" &&
      identityProvider.config.clientAuthMethod === "client_secret_post" &&
      identityProvider.config.defaultScope === "openid" &&
      identityProvider.config.syncMode === "FORCE" &&
      identityProvider.config.validateSignature === "true" &&
      identityProvider.config.useJwksUrl === "true" &&
      identityProvider.config.jwksUrl ===
        "http://host.docker.internal:3001/jwks" &&
      identityProvider.config.pkceEnabled === "true" &&
      identityProvider.config.pkceMethod === "S256",
    "Verana Wallet signature, JWKS, client authentication, or PKCE config is invalid",
  );
  console.log("PASS IdP: verana-wallet");
  console.log("PASS signature validation: broker JWKS");

  const flows = await requestJson<AuthenticationFlowRepresentation[]>(
    `/admin/realms/${realmName}/authentication/flows`,
    accessToken,
  );
  const firstLoginFlow = flows.find(
    (flow) => flow.alias === "verana first broker login",
  );
  requireCondition(
    firstLoginFlow?.builtIn === false && firstLoginFlow.topLevel === true,
    "Missing custom Verana first broker login flow",
  );
  const flowExecutions = await requestJson<
    AuthenticationExecutionRepresentation[]
  >(
    `/admin/realms/${realmName}/authentication/flows/${encodeURIComponent(
      "verana first broker login",
    )}/executions`,
    accessToken,
  );
  requireCondition(
    flowExecutions.length === 1 &&
      flowExecutions[0]?.providerId === "idp-create-user-if-unique" &&
      flowExecutions[0].requirement === "REQUIRED",
    "First broker login flow is not create-if-unique only",
  );
  console.log("PASS first login: JIT create-if-unique only");

  const mappers = await requestJson<MapperRepresentation[]>(
    `/admin/realms/${realmName}/identity-provider/instances/${identityProviderAlias}/mappers`,
    accessToken,
  );
  const groupMapper = getMapper(mappers, "ACME organization group");
  requireCondition(
    groupMapper.identityProviderMapper === "oidc-advanced-group-idp-mapper" &&
      groupMapper.config?.syncMode === "FORCE" &&
      groupMapper.config.claims === '[{"key":"organization","value":"ACME"}]' &&
      groupMapper.config["are.claim.values.regex"] === "false" &&
      groupMapper.config.group === "/organizations/acme",
    "ACME organization mapper is invalid",
  );
  console.log("PASS group mapper: organization=ACME");

  const roleMapper = getMapper(mappers, "Employee role");
  requireCondition(
    roleMapper.identityProviderMapper === "oidc-role-idp-mapper" &&
      roleMapper.config?.syncMode === "FORCE" &&
      roleMapper.config.claim === "role" &&
      roleMapper.config["claim.value"] === "employee" &&
      roleMapper.config.role === "employee",
    "Employee role mapper is invalid",
  );
  console.log("PASS role mapper: role=employee");

  const subjectMapper = getMapper(mappers, "Verana pairwise subject");
  requireCondition(
    subjectMapper.identityProviderMapper === "oidc-user-attribute-idp-mapper" &&
      subjectMapper.config?.syncMode === "FORCE" &&
      subjectMapper.config.claim === "sub" &&
      subjectMapper.config["user.attribute"] === "verana_subject" &&
      subjectMapper.config["allow.nullable.property"] === "false",
    "Verana pairwise subject mapper is invalid",
  );
  console.log("PASS subject mapper: sub to verana_subject");

  const protocolMappers = await requestJson<ProtocolMapperRepresentation[]>(
    `/admin/realms/${realmName}/clients/${client.id}/protocol-mappers/models`,
    accessToken,
  );
  const subjectProtocolMapper = getProtocolMapper(
    protocolMappers,
    "verana subject",
  );
  const groupProtocolMapper = getProtocolMapper(
    protocolMappers,
    "organization groups",
  );
  const roleProtocolMapper = getProtocolMapper(protocolMappers, "realm roles");
  requireCondition(
    subjectProtocolMapper.protocolMapper ===
      "oidc-usermodel-attribute-mapper" &&
      subjectProtocolMapper.config?.["user.attribute"] === "verana_subject" &&
      subjectProtocolMapper.config["claim.name"] === "verana_subject" &&
      subjectProtocolMapper.config["jsonType.label"] === "String" &&
      subjectProtocolMapper.config.multivalued === "false" &&
      subjectProtocolMapper.config["id.token.claim"] === "true" &&
      subjectProtocolMapper.config["access.token.claim"] === "true" &&
      subjectProtocolMapper.config["userinfo.token.claim"] === "true",
    "Verana subject protocol mapper is invalid",
  );
  requireCondition(
    groupProtocolMapper.protocolMapper === "oidc-group-membership-mapper" &&
      groupProtocolMapper.config?.["full.path"] === "true" &&
      groupProtocolMapper.config["claim.name"] === "groups" &&
      groupProtocolMapper.config["id.token.claim"] === "true" &&
      groupProtocolMapper.config["access.token.claim"] === "true" &&
      groupProtocolMapper.config["userinfo.token.claim"] === "true",
    "Organization group protocol mapper is invalid",
  );
  requireCondition(
    roleProtocolMapper.protocolMapper === "oidc-usermodel-realm-role-mapper" &&
      roleProtocolMapper.config?.["claim.name"] === "realm_access.roles" &&
      roleProtocolMapper.config["jsonType.label"] === "String" &&
      roleProtocolMapper.config.multivalued === "true" &&
      roleProtocolMapper.config["id.token.claim"] === "true" &&
      roleProtocolMapper.config["access.token.claim"] === "true" &&
      roleProtocolMapper.config["userinfo.token.claim"] === "true",
    "Realm role protocol mapper is invalid",
  );
  console.log("PASS app claims: subject, full groups, and realm roles");

  const groups = await requestJson<GroupRepresentation[]>(
    `/admin/realms/${realmName}/groups?search=organizations&exact=true`,
    accessToken,
  );
  const organizations = groups.find((group) => group.name === "organizations");
  requireCondition(organizations?.id, "Missing /organizations group");
  const organizationChildren = await requestJson<GroupRepresentation[]>(
    `/admin/realms/${realmName}/groups/${organizations.id}/children`,
    accessToken,
  );
  requireCondition(
    organizationChildren.some(
      (group) => group.name === "acme" && group.path === "/organizations/acme",
    ),
    "Missing /organizations/acme group",
  );
  const employeeRole = await requestJson<RoleRepresentation>(
    `/admin/realms/${realmName}/roles/employee`,
    accessToken,
  );
  requireCondition(employeeRole.name === "employee", "Missing employee role");
  const userCount = await requestJson<number>(
    `/admin/realms/${realmName}/users/count`,
    accessToken,
  );
  requireCondition(
    userCount === 0,
    "Disposable realm contains a pre-created user",
  );
  console.log("PASS authorization targets: /organizations/acme and employee");
  console.log("PASS users: no pre-created account");
};

await verify();
