import {
  Alert,
  Anchor,
  Box,
  Button,
  Card,
  Center,
  Group,
  PasswordInput,
  PinInput,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { IconAlertCircle, IconCircleCheck, IconLock } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { type FormEvent, type ReactNode, useEffect, useState } from "react";
import { Link, Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { useMe } from "../../api/auth";
import { api, errorMessage } from "../../api/client";
import type { Me } from "../../api/types";
import { Wordmark } from "../../components/ui";

export function AuthFrame({ title, subtitle, children }: { title: string; subtitle?: ReactNode; children: ReactNode }) {
  return (
    <Box className="cw-hero" mih="100vh" py={48} px="md">
      <Center>
        <Stack w="100%" maw={430} gap="lg">
          <Center>
            <Link to="/" style={{ textDecoration: "none" }}>
              <Wordmark inverted />
            </Link>
          </Center>
          <Card p="xl" radius="lg" shadow="lg" style={{ background: "var(--cw-white)", color: "var(--cw-navy)" }} withBorder={false}>
            <Title order={2} c="navy.8">
              {title}
            </Title>
            {subtitle && (
              <Text size="sm" c="dimmed" mt={4} mb="md">
                {subtitle}
              </Text>
            )}
            <Box mt="md">{children}</Box>
          </Card>
          <Text size="xs" c="gray.5" ta="center">
            Continuous Monitoring. Smarter Protection. Greater Trust.
          </Text>
        </Stack>
      </Center>
    </Box>
  );
}

function FormError({ error }: { error: string | null }) {
  return error ? (
    <Alert color="threat" variant="light" icon={<IconAlertCircle />} role="alert" mb="md">
      {error}
    </Alert>
  ) : null;
}

function landingFor(me: Me): string {
  if (me.memberships.length) return `/app/${me.memberships[0].tenant_id}/overview`;
  if (me.is_platform_staff) return me.platform_mfa_required ? "/staff/security" : "/admin";
  return "/login";
}

export function LoginPage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<"password" | "mfa">("password");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [useRecovery, setUseRecovery] = useState(false);

  const finish = (me: Me) => {
    qc.setQueryData(["me"], me);
    const next = params.get("next");
    navigate(next && next.startsWith("/") && !next.startsWith("//") ? next : landingFor(me), { replace: true });
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (step === "password") {
        const r = await api.post<{ mfa_required: boolean; user: Me | null }>("/auth/login", { email, password });
        if (r.mfa_required) setStep("mfa");
        else if (r.user) finish(r.user);
      } else {
        const r = await api.post<{ user: Me }>("/auth/mfa/verify", { code });
        finish(r.user);
      }
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthFrame
      title={step === "password" ? "Sign in" : "Verify it's you"}
      subtitle={step === "password" ? "Access your CyberWatch security console." : "Enter the 6-digit code from your authenticator app."}
    >
      <FormError error={error} />
      <form onSubmit={submit} noValidate>
        {step === "password" ? (
          <Stack>
            <TextInput label="Email address" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
            <PasswordInput label="Password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
            <Group justify="flex-end">
              <Anchor component={Link} to="/forgot-password" size="sm">
                Forgot password?
              </Anchor>
            </Group>
            <Button type="submit" loading={busy} fullWidth leftSection={<IconLock size={16} />}>
              Sign in
            </Button>
          </Stack>
        ) : (
          <Stack>
            {useRecovery ? (
              <TextInput label="Recovery code" value={code} onChange={(e) => setCode(e.currentTarget.value)} autoComplete="one-time-code" />
            ) : (
              <Center>
                <PinInput length={6} type="number" oneTimeCode value={code} onChange={setCode} aria-label="Authentication code" autoFocus />
              </Center>
            )}
            <Button type="submit" loading={busy} fullWidth disabled={code.length < 6}>
              Verify
            </Button>
            <Anchor component="button" type="button" size="sm" onClick={() => { setUseRecovery(!useRecovery); setCode(""); }}>
              {useRecovery ? "Use authenticator code" : "Use a recovery code instead"}
            </Anchor>
          </Stack>
        )}
      </form>
      {step === "password" && (
        <Text size="sm" ta="center" mt="lg" c="dimmed">
          New to CyberWatch?{" "}
          <Anchor component={Link} to="/register">
            Create an account
          </Anchor>
        </Text>
      )}
    </AuthFrame>
  );
}

export function RegisterPage() {
  const [form, setForm] = useState({ full_name: "", email: "", organisation_name: "", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.currentTarget.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.post("/auth/register", form);
      setDone(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  if (done)
    return (
      <AuthFrame title="Check your email">
        <Alert color="secure" icon={<IconCircleCheck />} variant="light">
          Your account and organisation were created with a trial plan. We sent a verification link to <b>{form.email}</b>.
        </Alert>
        <Button component={Link} to="/login" fullWidth mt="md">
          Continue to sign in
        </Button>
      </AuthFrame>
    );

  return (
    <AuthFrame title="Create your account" subtitle="Start monitoring your websites. A trial plan is applied automatically.">
      <FormError error={error} />
      <form onSubmit={submit}>
        <Stack>
          <TextInput label="Full name" required value={form.full_name} onChange={set("full_name")} autoComplete="name" />
          <TextInput label="Work email" type="email" required value={form.email} onChange={set("email")} autoComplete="email" />
          <TextInput label="Organisation name" required value={form.organisation_name} onChange={set("organisation_name")} autoComplete="organization" />
          <PasswordInput
            label="Password"
            description="At least 12 characters. Avoid reusing passwords from other sites."
            required
            value={form.password}
            onChange={set("password")}
            autoComplete="new-password"
          />
          <Button type="submit" loading={busy} fullWidth>
            Create account
          </Button>
          <Text size="xs" c="dimmed">
            By creating an account you confirm you are authorised to monitor the websites and hosting accounts you connect.
          </Text>
        </Stack>
      </form>
      <Text size="sm" ta="center" mt="lg" c="dimmed">
        Already have an account?{" "}
        <Anchor component={Link} to="/login">
          Sign in
        </Anchor>
      </Text>
    </AuthFrame>
  );
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  return (
    <AuthFrame title="Reset your password" subtitle="We'll email you a link to set a new password.">
      <FormError error={error} />
      {msg ? (
        <Alert color="secure" variant="light">
          {msg}
        </Alert>
      ) : (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              const r = await api.post<{ message: string }>("/auth/password/forgot", { email });
              setMsg(r.message);
            } catch (err) {
              setError(errorMessage(err));
            }
          }}
        >
          <Stack>
            <TextInput label="Email address" type="email" required value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
            <Button type="submit" fullWidth>
              Send reset link
            </Button>
          </Stack>
        </form>
      )}
      <Anchor component={Link} to="/login" size="sm" mt="md" display="block" ta="center">
        Back to sign in
      </Anchor>
    </AuthFrame>
  );
}

export function ResetPasswordPage() {
  const [params] = useSearchParams();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  return (
    <AuthFrame title="Choose a new password">
      <FormError error={error} />
      {done ? (
        <>
          <Alert color="secure" variant="light">
            Password updated. All existing sessions were signed out.
          </Alert>
          <Button component={Link} to="/login" fullWidth mt="md">
            Sign in
          </Button>
        </>
      ) : (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api.post("/auth/password/reset", { token: params.get("token") ?? "", password });
              setDone(true);
            } catch (err) {
              setError(errorMessage(err));
            }
          }}
        >
          <Stack>
            <PasswordInput label="New password" description="At least 12 characters." required value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoComplete="new-password" />
            <Button type="submit" fullWidth>
              Update password
            </Button>
          </Stack>
        </form>
      )}
    </AuthFrame>
  );
}

export function VerifyEmailPage() {
  const [params] = useSearchParams();
  const [state, setState] = useState<"working" | "ok" | "error">("working");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api
      .post("/auth/verify-email", { token: params.get("token") ?? "" })
      .then(() => setState("ok"))
      .catch((e) => {
        setError(errorMessage(e));
        setState("error");
      });
  }, [params]);
  return (
    <AuthFrame title="Email verification">
      {state === "working" && <Text>Verifying…</Text>}
      {state === "ok" && (
        <Alert color="secure" variant="light" icon={<IconCircleCheck />}>
          Your email address is verified.
        </Alert>
      )}
      <FormError error={error} />
      <Button component={Link} to="/login" fullWidth mt="md">
        Continue
      </Button>
    </AuthFrame>
  );
}

export function AcceptInvitePage() {
  const [params] = useSearchParams();
  const me = useMe();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const token = params.get("token") ?? "";
  if (me.isLoading) return <AuthFrame title="Invitation">Loading…</AuthFrame>;
  if (me.error)
    return (
      <AuthFrame title="You've been invited" subtitle="Sign in or create an account with the invited email address, then return to this link.">
        <Stack>
          <Button component={Link} to={`/login?next=${encodeURIComponent(`/invite?token=${token}`)}`}>
            Sign in
          </Button>
          <Button variant="default" component={Link} to="/register">
            Create an account
          </Button>
        </Stack>
      </AuthFrame>
    );
  return (
    <AuthFrame title="Join organisation" subtitle={`Signed in as ${me.data?.email}.`}>
      <FormError error={error} />
      <Button
        fullWidth
        onClick={async () => {
          try {
            await api.post("/invitations/accept", { token });
            await qc.invalidateQueries({ queryKey: ["me"] });
            const fresh = await api.get<Me>("/auth/me");
            navigate(landingFor(fresh));
          } catch (e) {
            setError(errorMessage(e));
          }
        }}
      >
        Accept invitation
      </Button>
    </AuthFrame>
  );
}

/** /app entry point: send the user to their first organisation (or staff console). */
export function AppEntryRedirect() {
  const me = useMe();
  if (me.isLoading) return null;
  return <Navigate to={me.data ? landingFor(me.data) : "/login"} replace />;
}
