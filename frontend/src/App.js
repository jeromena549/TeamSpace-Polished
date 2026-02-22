import { useState, useEffect, createContext, useContext } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useParams, Link } from "react-router-dom";
import axios from "axios";
import { Toaster, toast } from "sonner";

// Import shadcn components
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger,
  DropdownMenuSeparator 
} from "@/components/ui/dropdown-menu";

// Lucide icons
import { 
  Search, Send, LogOut, User, Users, MessageSquare, 
  Mail, Building2, Briefcase, Tag, Edit2, ArrowLeft,
  RefreshCw, Eye, EyeOff, Loader2, ChevronDown
} from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Configure axios defaults
axios.defaults.withCredentials = true;

// Auth Context
const AuthContext = createContext(null);

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const checkAuth = async () => {
    try {
      const response = await axios.get(`${API}/auth/me`);
      setUser(response.data);
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const login = async (email, password) => {
    const response = await axios.post(`${API}/auth/login`, { email, password });
    setUser(response.data.user);
    return response.data;
  };

  const signup = async (email, password, name, inviteCode) => {
    const response = await axios.post(`${API}/auth/signup`, { email, password, name, inviteCode });
    setUser(response.data.user);
    return response.data;
  };

  const logout = async () => {
    await axios.post(`${API}/auth/logout`);
    setUser(null);
  };

  const updateUser = (updates) => {
    setUser(prev => ({ ...prev, ...updates }));
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, logout, updateUser, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return children;
};

// Get initials from name
const getInitials = (name) => {
  if (!name) return "?";
  return name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2);
};

// Format date
const formatDate = (dateString) => {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};

// Header Component
const Header = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
      toast.success("Logged out successfully");
    } catch (error) {
      toast.error("Failed to logout");
    }
  };

  return (
    <header className="bg-white/80 backdrop-blur-md border-b border-slate-200/50 sticky top-0 z-50" data-testid="main-header">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <Link to="/members" className="flex items-center gap-2" data-testid="logo-link">
            <div className="w-8 h-8 bg-slate-800 rounded-lg flex items-center justify-center">
              <Users className="h-4 w-4 text-white" />
            </div>
            <span className="font-semibold text-xl text-slate-800" style={{ fontFamily: 'Outfit, sans-serif' }}>Sync</span>
          </Link>

          <nav className="hidden md:flex items-center gap-1">
            <Button variant="ghost" className="text-slate-600 hover:text-slate-900" onClick={() => navigate("/members")} data-testid="nav-members">
              <Users className="h-4 w-4 mr-2" />
              Members
            </Button>
            <Button variant="ghost" className="text-slate-600 hover:text-slate-900" onClick={() => navigate("/messages")} data-testid="nav-messages">
              <MessageSquare className="h-4 w-4 mr-2" />
              Messages
            </Button>
          </nav>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="flex items-center gap-2" data-testid="user-menu-trigger">
                <Avatar className="h-8 w-8">
                  <AvatarImage src={user?.avatarUrl} alt={user?.name} />
                  <AvatarFallback className="bg-slate-700 text-white text-xs">{getInitials(user?.name)}</AvatarFallback>
                </Avatar>
                <span className="hidden sm:block text-sm font-medium text-slate-700">{user?.name}</span>
                <ChevronDown className="h-4 w-4 text-slate-400" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem onClick={() => navigate("/me")} data-testid="menu-profile">
                <User className="h-4 w-4 mr-2" />
                My Profile
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => navigate("/members")} className="md:hidden" data-testid="menu-members-mobile">
                <Users className="h-4 w-4 mr-2" />
                Members
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => navigate("/messages")} className="md:hidden" data-testid="menu-messages-mobile">
                <MessageSquare className="h-4 w-4 mr-2" />
                Messages
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout} className="text-red-600" data-testid="menu-logout">
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  );
};

// Login Page
const LoginPage = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { login, user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (user) navigate("/members");
  }, [user, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login(email, password);
      toast.success("Welcome back!");
      navigate("/members");
    } catch (error) {
      const detail = error.response?.data?.detail;
      let errorMessage = "Invalid credentials";
      if (typeof detail === "string") {
        errorMessage = detail;
      } else if (Array.isArray(detail) && detail.length > 0) {
        errorMessage = detail[0]?.msg || detail[0]?.message || errorMessage;
      }
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-background flex items-center justify-center p-4" data-testid="login-page">
      <Card className="w-full max-w-md animate-slide-up">
        <CardHeader className="text-center pb-2">
          <div className="w-12 h-12 bg-slate-800 rounded-xl flex items-center justify-center mx-auto mb-4">
            <Users className="h-6 w-6 text-white" />
          </div>
          <CardTitle className="text-2xl" style={{ fontFamily: 'Outfit, sans-serif' }}>Welcome to Sync</CardTitle>
          <CardDescription>Sign in to connect with your team</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                data-testid="login-email"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                data-testid="login-password"
              />
            </div>
            <Button type="submit" className="w-full bg-slate-800 hover:bg-slate-700" disabled={loading} data-testid="login-submit">
              {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Sign In
            </Button>
          </form>
          <div className="mt-6 text-center space-y-2">
            <Link to="/forgot-password" className="text-sm text-slate-600 hover:text-slate-900" data-testid="forgot-password-link">
              Forgot your password?
            </Link>
            <p className="text-sm text-slate-600">
              Don't have an account?{" "}
              <Link to="/signup" className="text-slate-900 font-medium hover:underline" data-testid="signup-link">
                Sign up
              </Link>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Signup Page
const SignupPage = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [loading, setLoading] = useState(false);
  const { signup, user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (user) navigate("/members");
  }, [user, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await signup(email, password, name, inviteCode || undefined);
      toast.success("Account created! Welcome to Sync");
      navigate("/me");
    } catch (error) {
      // Handle validation errors (can be array or string)
      const detail = error.response?.data?.detail;
      let errorMessage = "Failed to create account";
      if (typeof detail === "string") {
        errorMessage = detail;
      } else if (Array.isArray(detail) && detail.length > 0) {
        errorMessage = detail[0]?.msg || detail[0]?.message || errorMessage;
      } else if (detail?.msg) {
        errorMessage = detail.msg;
      }
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-background flex items-center justify-center p-4" data-testid="signup-page">
      <Card className="w-full max-w-md animate-slide-up">
        <CardHeader className="text-center pb-2">
          <div className="w-12 h-12 bg-slate-800 rounded-xl flex items-center justify-center mx-auto mb-4">
            <Users className="h-6 w-6 text-white" />
          </div>
          <CardTitle className="text-2xl" style={{ fontFamily: 'Outfit, sans-serif' }}>Join Sync</CardTitle>
          <CardDescription>Create your account with company email</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Full Name</Label>
              <Input
                id="name"
                type="text"
                placeholder="John Doe"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                minLength={2}
                data-testid="signup-name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Company Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                data-testid="signup-email"
              />
              <p className="text-xs text-slate-500">Must end with @company.com</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Minimum 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
                data-testid="signup-password"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="inviteCode">Invite Code (Optional)</Label>
              <Input
                id="inviteCode"
                type="text"
                placeholder="Enter invite code if required"
                value={inviteCode}
                onChange={(e) => setInviteCode(e.target.value)}
                data-testid="signup-invite"
              />
            </div>
            <Button type="submit" className="w-full bg-slate-800 hover:bg-slate-700" disabled={loading} data-testid="signup-submit">
              {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Create Account
            </Button>
          </form>
          <p className="mt-6 text-center text-sm text-slate-600">
            Already have an account?{" "}
            <Link to="/login" className="text-slate-900 font-medium hover:underline" data-testid="login-link">
              Sign in
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

// Forgot Password Page
const ForgotPasswordPage = () => {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await axios.post(`${API}/auth/forgot-password`, { email });
      setToken(response.data.token || "");
      toast.success("Check console/logs for reset token (homework version)");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to send reset email");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-background flex items-center justify-center p-4" data-testid="forgot-password-page">
      <Card className="w-full max-w-md animate-slide-up">
        <CardHeader className="text-center pb-2">
          <CardTitle className="text-2xl" style={{ fontFamily: 'Outfit, sans-serif' }}>Reset Password</CardTitle>
          <CardDescription>Enter your email to receive a reset token</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                data-testid="forgot-email"
              />
            </div>
            <Button type="submit" className="w-full bg-slate-800 hover:bg-slate-700" disabled={loading} data-testid="forgot-submit">
              {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Send Reset Token
            </Button>
          </form>
          {token && (
            <div className="mt-4 p-4 bg-emerald-50 border border-emerald-200 rounded-lg" data-testid="reset-token-display">
              <p className="text-sm font-medium text-emerald-800">Reset Token (homework version):</p>
              <code className="text-xs break-all text-emerald-700">{token}</code>
              <Link to="/reset-password" className="block mt-2 text-sm text-emerald-600 hover:underline">
                Go to reset password page →
              </Link>
            </div>
          )}
          <p className="mt-6 text-center text-sm text-slate-600">
            <Link to="/login" className="text-slate-900 font-medium hover:underline" data-testid="back-to-login">
              Back to login
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

// Reset Password Page
const ResetPasswordPage = () => {
  const [token, setToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await axios.post(`${API}/auth/reset-password`, { token, newPassword });
      toast.success("Password reset! Please login with your new password");
      navigate("/login");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to reset password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-background flex items-center justify-center p-4" data-testid="reset-password-page">
      <Card className="w-full max-w-md animate-slide-up">
        <CardHeader className="text-center pb-2">
          <CardTitle className="text-2xl" style={{ fontFamily: 'Outfit, sans-serif' }}>Set New Password</CardTitle>
          <CardDescription>Enter the reset token and your new password</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="token">Reset Token</Label>
              <Input
                id="token"
                type="text"
                placeholder="Paste your reset token"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                required
                data-testid="reset-token"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="newPassword">New Password</Label>
              <Input
                id="newPassword"
                type="password"
                placeholder="Minimum 8 characters"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                minLength={8}
                data-testid="reset-new-password"
              />
            </div>
            <Button type="submit" className="w-full bg-slate-800 hover:bg-slate-700" disabled={loading} data-testid="reset-submit">
              {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Reset Password
            </Button>
          </form>
          <p className="mt-6 text-center text-sm text-slate-600">
            <Link to="/login" className="text-slate-900 font-medium hover:underline">
              Back to login
            </Link>
          </p>
        </CardContent>
      </Card>
    </div>
  );
};

// Profile Page
const ProfilePage = () => {
  const { user, updateUser } = useAuth();
  const [editing, setEditing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    name: "",
    department: "",
    title: "",
    skills: "",
    bio: "",
    avatarUrl: "",
    showEmail: true
  });

  useEffect(() => {
    if (user) {
      setForm({
        name: user.name || "",
        department: user.department || "",
        title: user.title || "",
        skills: (user.skills || []).join(", "),
        bio: user.bio || "",
        avatarUrl: user.avatarUrl || "",
        showEmail: user.showEmail !== false
      });
    }
  }, [user]);

  const handleSave = async () => {
    setLoading(true);
    try {
      const updates = {
        name: form.name,
        department: form.department || null,
        title: form.title || null,
        skills: form.skills ? form.skills.split(",").map(s => s.trim()).filter(Boolean) : [],
        bio: form.bio || null,
        avatarUrl: form.avatarUrl || null,
        showEmail: form.showEmail
      };
      const response = await axios.put(`${API}/users/me`, updates);
      updateUser(response.data);
      setEditing(false);
      toast.success("Profile updated!");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to update profile");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50" data-testid="profile-page">
      <Header />
      <main className="max-w-2xl mx-auto px-4 py-8">
        <Card className="animate-fade-in">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <CardTitle className="text-2xl" style={{ fontFamily: 'Outfit, sans-serif' }}>My Profile</CardTitle>
              <Button
                variant={editing ? "outline" : "default"}
                onClick={() => editing ? setEditing(false) : setEditing(true)}
                className={editing ? "" : "bg-slate-800 hover:bg-slate-700"}
                data-testid="edit-profile-btn"
              >
                <Edit2 className="h-4 w-4 mr-2" />
                {editing ? "Cancel" : "Edit Profile"}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Avatar */}
            <div className="flex items-center gap-4">
              <Avatar className="h-20 w-20">
                <AvatarImage src={form.avatarUrl} alt={form.name} />
                <AvatarFallback className="bg-slate-700 text-white text-xl">{getInitials(form.name)}</AvatarFallback>
              </Avatar>
              {editing && (
                <div className="flex-1">
                  <Label htmlFor="avatarUrl">Avatar URL</Label>
                  <Input
                    id="avatarUrl"
                    placeholder="https://example.com/avatar.jpg"
                    value={form.avatarUrl}
                    onChange={(e) => setForm({ ...form, avatarUrl: e.target.value })}
                    data-testid="profile-avatar-input"
                  />
                </div>
              )}
            </div>

            <Separator />

            {/* Form fields */}
            <div className="grid gap-4">
              <div className="grid sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="name">
                    <User className="h-4 w-4 inline mr-1" />
                    Full Name
                  </Label>
                  {editing ? (
                    <Input
                      id="name"
                      value={form.name}
                      onChange={(e) => setForm({ ...form, name: e.target.value })}
                      data-testid="profile-name-input"
                    />
                  ) : (
                    <p className="text-slate-700 py-2">{form.name}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">
                    <Mail className="h-4 w-4 inline mr-1" />
                    Email
                  </Label>
                  <p className="text-slate-700 py-2">{user?.email}</p>
                </div>
              </div>

              <div className="grid sm:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="department">
                    <Building2 className="h-4 w-4 inline mr-1" />
                    Department
                  </Label>
                  {editing ? (
                    <Input
                      id="department"
                      placeholder="Engineering"
                      value={form.department}
                      onChange={(e) => setForm({ ...form, department: e.target.value })}
                      data-testid="profile-department-input"
                    />
                  ) : (
                    <p className="text-slate-700 py-2">{form.department || "Not set"}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="title">
                    <Briefcase className="h-4 w-4 inline mr-1" />
                    Job Title
                  </Label>
                  {editing ? (
                    <Input
                      id="title"
                      placeholder="Software Engineer"
                      value={form.title}
                      onChange={(e) => setForm({ ...form, title: e.target.value })}
                      data-testid="profile-title-input"
                    />
                  ) : (
                    <p className="text-slate-700 py-2">{form.title || "Not set"}</p>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="skills">
                  <Tag className="h-4 w-4 inline mr-1" />
                  Skills
                </Label>
                {editing ? (
                  <>
                    <Input
                      id="skills"
                      placeholder="React, Node.js, Python"
                      value={form.skills}
                      onChange={(e) => setForm({ ...form, skills: e.target.value })}
                      data-testid="profile-skills-input"
                    />
                    <p className="text-xs text-slate-500">Separate skills with commas</p>
                  </>
                ) : (
                  <div className="flex flex-wrap gap-2 py-2">
                    {(user?.skills || []).length > 0 ? (
                      user.skills.map((skill, i) => (
                        <Badge key={i} variant="secondary" className="bg-slate-100">{skill}</Badge>
                      ))
                    ) : (
                      <span className="text-slate-500">No skills added</span>
                    )}
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="bio">Bio</Label>
                {editing ? (
                  <Textarea
                    id="bio"
                    placeholder="Tell us about yourself..."
                    value={form.bio}
                    onChange={(e) => setForm({ ...form, bio: e.target.value })}
                    rows={3}
                    data-testid="profile-bio-input"
                  />
                ) : (
                  <p className="text-slate-700 py-2">{form.bio || "No bio added"}</p>
                )}
              </div>

              {/* Privacy setting */}
              <Separator />
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-base">
                    {form.showEmail ? <Eye className="h-4 w-4 inline mr-1" /> : <EyeOff className="h-4 w-4 inline mr-1" />}
                    Show Email to Others
                  </Label>
                  <p className="text-sm text-slate-500">Allow other members to see your email address</p>
                </div>
                <Switch
                  checked={form.showEmail}
                  onCheckedChange={(checked) => setForm({ ...form, showEmail: checked })}
                  disabled={!editing}
                  data-testid="profile-show-email-switch"
                />
              </div>
            </div>

            {editing && (
              <div className="flex gap-3 pt-4">
                <Button onClick={handleSave} className="bg-slate-800 hover:bg-slate-700" disabled={loading} data-testid="save-profile-btn">
                  {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                  Save Changes
                </Button>
                <Button variant="outline" onClick={() => setEditing(false)} data-testid="cancel-edit-btn">
                  Cancel
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
};

// Members Directory Page
const MembersPage = () => {
  const [members, setMembers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const navigate = useNavigate();

  const fetchMembers = async (query = "") => {
    setLoading(true);
    try {
      const params = query ? { search: query } : {};
      const response = await axios.get(`${API}/users`, { params });
      setMembers(response.data);
    } catch (error) {
      toast.error("Failed to load members");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMembers();
  }, []);

  const handleSearch = (e) => {
    e.preventDefault();
    fetchMembers(search);
  };

  return (
    <div className="min-h-screen bg-slate-50" data-testid="members-page">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-slate-900 mb-2" style={{ fontFamily: 'Outfit, sans-serif' }}>Team Directory</h1>
          <p className="text-slate-600">Find and connect with your colleagues</p>
        </div>

        {/* Search */}
        <form onSubmit={handleSearch} className="mb-8 flex gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
            <Input
              placeholder="Search by name, department, or skills..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-10 search-input"
              data-testid="search-input"
            />
          </div>
          <Button type="submit" className="bg-slate-800 hover:bg-slate-700" data-testid="search-btn">
            Search
          </Button>
          {search && (
            <Button type="button" variant="outline" onClick={() => { setSearch(""); fetchMembers(); }} data-testid="clear-search-btn">
              Clear
            </Button>
          )}
        </form>

        {/* Members Grid */}
        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
          </div>
        ) : members.length === 0 ? (
          <div className="text-center py-12" data-testid="no-members">
            <Users className="h-12 w-12 text-slate-300 mx-auto mb-4" />
            <p className="text-slate-500">No members found</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6" data-testid="members-grid">
            {members.map((member) => (
              <Card key={member.id} className="member-card cursor-pointer group hover:border-slate-300" onClick={() => navigate(`/members/${member.id}`)} data-testid={`member-card-${member.id}`}>
                <CardContent className="p-6">
                  <div className="flex items-start gap-4">
                    <div className="relative">
                      <Avatar className="h-14 w-14">
                        <AvatarImage src={member.avatarUrl} alt={member.name} />
                        <AvatarFallback className="bg-slate-700 text-white">{getInitials(member.name)}</AvatarFallback>
                      </Avatar>
                      {member.isOnline && (
                        <span className="absolute bottom-0 right-0 block h-3.5 w-3.5 rounded-full bg-emerald-500 ring-2 ring-white" data-testid="online-indicator" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-slate-900 truncate group-hover:text-slate-700">{member.name}</h3>
                      <p className="text-sm text-slate-500 truncate">{member.title || "Team Member"}</p>
                      {member.department && (
                        <p className="text-xs text-slate-400 mt-1">{member.department}</p>
                      )}
                    </div>
                  </div>
                  {member.skills && member.skills.length > 0 && (
                    <div className="mt-4 flex flex-wrap gap-1.5">
                      {member.skills.slice(0, 3).map((skill, i) => (
                        <Badge key={i} variant="secondary" className="bg-slate-100 text-xs">{skill}</Badge>
                      ))}
                      {member.skills.length > 3 && (
                        <Badge variant="secondary" className="bg-slate-100 text-xs">+{member.skills.length - 3}</Badge>
                      )}
                    </div>
                  )}
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full mt-4 opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={(e) => { e.stopPropagation(); navigate(`/messages/${member.id}`); }}
                    data-testid={`message-btn-${member.id}`}
                  >
                    <MessageSquare className="h-4 w-4 mr-2" />
                    Message
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
    </div>
  );
};

// Member Profile Page
const MemberProfilePage = () => {
  const { id } = useParams();
  const [member, setMember] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    const fetchMember = async () => {
      try {
        const response = await axios.get(`${API}/users/${id}`);
        setMember(response.data);
      } catch (error) {
        toast.error("Member not found");
        navigate("/members");
      } finally {
        setLoading(false);
      }
    };
    fetchMember();
  }, [id, navigate]);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Header />
        <div className="flex justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
        </div>
      </div>
    );
  }

  if (!member) return null;

  const isOwnProfile = user?.id === member.id;

  return (
    <div className="min-h-screen bg-slate-50" data-testid="member-profile-page">
      <Header />
      <main className="max-w-2xl mx-auto px-4 py-8">
        <Button variant="ghost" onClick={() => navigate("/members")} className="mb-4" data-testid="back-to-members">
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Directory
        </Button>

        <Card className="animate-fade-in">
          <CardContent className="p-8">
            <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6 mb-6">
              <div className="relative">
                <Avatar className="h-24 w-24">
                  <AvatarImage src={member.avatarUrl} alt={member.name} />
                  <AvatarFallback className="bg-slate-700 text-white text-2xl">{getInitials(member.name)}</AvatarFallback>
                </Avatar>
                {member.isOnline && (
                  <span className="absolute bottom-1 right-1 block h-4 w-4 rounded-full bg-emerald-500 ring-2 ring-white" />
                )}
              </div>
              <div className="text-center sm:text-left flex-1">
                <h1 className="text-2xl font-bold text-slate-900" style={{ fontFamily: 'Outfit, sans-serif' }}>{member.name}</h1>
                <p className="text-slate-600">{member.title || "Team Member"}</p>
                {member.department && (
                  <p className="text-sm text-slate-500 mt-1">{member.department}</p>
                )}
                <div className="flex items-center gap-2 mt-2 justify-center sm:justify-start">
                  {member.isOnline ? (
                    <Badge className="bg-emerald-100 text-emerald-700">Online</Badge>
                  ) : (
                    <Badge variant="secondary">
                      {member.lastSeenAt ? `Last seen ${formatDate(member.lastSeenAt)}` : "Offline"}
                    </Badge>
                  )}
                </div>
              </div>
            </div>

            <Separator className="my-6" />

            <div className="space-y-4">
              {member.email && (
                <div className="flex items-center gap-3">
                  <Mail className="h-5 w-5 text-slate-400" />
                  <a href={`mailto:${member.email}`} className="text-slate-700 hover:text-slate-900">{member.email}</a>
                </div>
              )}

              {member.skills && member.skills.length > 0 && (
                <div>
                  <h3 className="text-sm font-medium text-slate-500 mb-2">Skills</h3>
                  <div className="flex flex-wrap gap-2">
                    {member.skills.map((skill, i) => (
                      <Badge key={i} variant="secondary" className="bg-slate-100">{skill}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {member.bio && (
                <div>
                  <h3 className="text-sm font-medium text-slate-500 mb-2">About</h3>
                  <p className="text-slate-700">{member.bio}</p>
                </div>
              )}
            </div>

            {!isOwnProfile && (
              <Button
                className="w-full mt-6 bg-slate-800 hover:bg-slate-700"
                onClick={() => navigate(`/messages/${member.id}`)}
                data-testid="send-message-btn"
              >
                <MessageSquare className="h-4 w-4 mr-2" />
                Send Message
              </Button>
            )}

            {isOwnProfile && (
              <Button
                variant="outline"
                className="w-full mt-6"
                onClick={() => navigate("/me")}
                data-testid="edit-own-profile-btn"
              >
                <Edit2 className="h-4 w-4 mr-2" />
                Edit Your Profile
              </Button>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
};

// Conversations List Page
const MessagesPage = () => {
  const [conversations, setConversations] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchConversations = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${API}/messages/conversations`);
      setConversations(response.data);
    } catch (error) {
      toast.error("Failed to load conversations");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchConversations();
  }, []);

  return (
    <div className="min-h-screen bg-slate-50" data-testid="messages-page">
      <Header />
      <main className="max-w-2xl mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-slate-900" style={{ fontFamily: 'Outfit, sans-serif' }}>Messages</h1>
            <p className="text-slate-600 text-sm">Your conversations</p>
          </div>
          <Button variant="outline" onClick={fetchConversations} data-testid="refresh-messages-btn">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        <Card>
          {loading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
            </div>
          ) : conversations.length === 0 ? (
            <div className="text-center py-12" data-testid="no-conversations">
              <MessageSquare className="h-12 w-12 text-slate-300 mx-auto mb-4" />
              <p className="text-slate-500 mb-4">No conversations yet</p>
              <Button onClick={() => navigate("/members")} className="bg-slate-800 hover:bg-slate-700">
                Find Someone to Chat With
              </Button>
            </div>
          ) : (
            <ScrollArea className="max-h-[600px]">
              {conversations.map((conv, index) => (
                <div key={conv.userId}>
                  <div
                    className="flex items-center gap-4 p-4 conversation-item cursor-pointer hover:bg-slate-50"
                    onClick={() => navigate(`/messages/${conv.userId}`)}
                    data-testid={`conversation-${conv.userId}`}
                  >
                    <div className="relative">
                      <Avatar className="h-12 w-12">
                        <AvatarImage src={conv.userAvatar} alt={conv.userName} />
                        <AvatarFallback className="bg-slate-700 text-white">{getInitials(conv.userName)}</AvatarFallback>
                      </Avatar>
                      {conv.isOnline && (
                        <span className="absolute bottom-0 right-0 block h-3 w-3 rounded-full bg-emerald-500 ring-2 ring-white" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <h3 className="font-medium text-slate-900 truncate">{conv.userName}</h3>
                        <span className="text-xs text-slate-400">{formatDate(conv.lastMessageAt)}</span>
                      </div>
                      <p className="text-sm text-slate-500 truncate">{conv.lastMessage}</p>
                    </div>
                  </div>
                  {index < conversations.length - 1 && <Separator />}
                </div>
              ))}
            </ScrollArea>
          )}
        </Card>
      </main>
    </div>
  );
};

// Chat Thread Page
const ChatThreadPage = () => {
  const { userId } = useParams();
  const [messages, setMessages] = useState([]);
  const [partner, setPartner] = useState(null);
  const [newMessage, setNewMessage] = useState("");
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const navigate = useNavigate();
  const { user } = useAuth();

  const fetchThread = async () => {
    try {
      const [threadRes, userRes] = await Promise.all([
        axios.get(`${API}/messages/thread/${userId}`),
        axios.get(`${API}/users/${userId}`)
      ]);
      setMessages(threadRes.data);
      setPartner(userRes.data);
    } catch (error) {
      toast.error("Failed to load conversation");
      navigate("/messages");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThread();
  }, [userId]);

  const handleSend = async (e) => {
    e.preventDefault();
    if (!newMessage.trim()) return;

    setSending(true);
    try {
      const response = await axios.post(`${API}/messages/thread/${userId}`, { body: newMessage });
      setMessages([...messages, response.data]);
      setNewMessage("");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to send message");
    } finally {
      setSending(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Header />
        <div className="flex justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col" data-testid="chat-thread-page">
      <Header />
      
      {/* Chat header */}
      <div className="bg-white border-b border-slate-200 px-4 py-3">
        <div className="max-w-2xl mx-auto flex items-center gap-4">
          <Button variant="ghost" size="sm" onClick={() => navigate("/messages")} data-testid="back-to-messages">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="relative" onClick={() => navigate(`/members/${userId}`)} style={{ cursor: 'pointer' }}>
            <Avatar className="h-10 w-10">
              <AvatarImage src={partner?.avatarUrl} alt={partner?.name} />
              <AvatarFallback className="bg-slate-700 text-white">{getInitials(partner?.name)}</AvatarFallback>
            </Avatar>
            {partner?.isOnline && (
              <span className="absolute bottom-0 right-0 block h-2.5 w-2.5 rounded-full bg-emerald-500 ring-2 ring-white" />
            )}
          </div>
          <div className="flex-1">
            <h2 className="font-semibold text-slate-900">{partner?.name}</h2>
            <p className="text-xs text-slate-500">
              {partner?.isOnline ? "Online" : partner?.lastSeenAt ? `Last seen ${formatDate(partner.lastSeenAt)}` : "Offline"}
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={fetchThread} data-testid="refresh-thread-btn">
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Messages */}
      <ScrollArea className="flex-1 px-4 py-6">
        <div className="max-w-2xl mx-auto space-y-4">
          {messages.length === 0 ? (
            <div className="text-center py-12" data-testid="no-messages">
              <MessageSquare className="h-12 w-12 text-slate-300 mx-auto mb-4" />
              <p className="text-slate-500">Start your conversation with {partner?.name}</p>
            </div>
          ) : (
            messages.map((msg) => {
              const isMine = msg.senderId === user?.id;
              return (
                <div key={msg.id} className={`flex ${isMine ? "justify-end" : "justify-start"}`} data-testid={`message-${msg.id}`}>
                  <div className={`max-w-[75%] px-4 py-2 ${isMine ? "message-sent" : "message-received"}`}>
                    <p className="text-sm whitespace-pre-wrap break-words">{msg.body}</p>
                    <p className={`text-xs mt-1 ${isMine ? "text-slate-300" : "text-slate-400"}`}>
                      {formatDate(msg.createdAt)}
                    </p>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>

      {/* Message input */}
      <div className="bg-white border-t border-slate-200 px-4 py-4">
        <form onSubmit={handleSend} className="max-w-2xl mx-auto flex gap-3">
          <Input
            placeholder="Type your message..."
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            className="flex-1"
            data-testid="message-input"
          />
          <Button type="submit" className="bg-slate-800 hover:bg-slate-700" disabled={sending || !newMessage.trim()} data-testid="send-message-btn">
            {sending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          </Button>
        </form>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  return (
    <div className="App">
      <Toaster position="top-center" richColors />
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/signup" element={<SignupPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />

            {/* Protected routes */}
            <Route path="/me" element={<ProtectedRoute><ProfilePage /></ProtectedRoute>} />
            <Route path="/members" element={<ProtectedRoute><MembersPage /></ProtectedRoute>} />
            <Route path="/members/:id" element={<ProtectedRoute><MemberProfilePage /></ProtectedRoute>} />
            <Route path="/messages" element={<ProtectedRoute><MessagesPage /></ProtectedRoute>} />
            <Route path="/messages/:userId" element={<ProtectedRoute><ChatThreadPage /></ProtectedRoute>} />

            {/* Redirect */}
            <Route path="/" element={<Navigate to="/login" replace />} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </div>
  );
}

export default App;
