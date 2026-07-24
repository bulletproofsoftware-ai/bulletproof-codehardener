export default function LoginLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Login page has a minimal layout without sidebar/header
  return <>{children}</>;
}
