import AuthGate from "@/components/AuthGate";
import ChatApp from "@/components/ChatApp";
import { AuthProvider } from "@/hooks/useAuth";

export default function HomePage() {
  // MVP-1: sin sesión se ve el login; con sesión (o con el login sin configurar, en modo demo) se ve el chat.
  return (
    <AuthProvider>
      <AuthGate>
        <ChatApp />
      </AuthGate>
    </AuthProvider>
  );
}
