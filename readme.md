# 🧠 AI Parenting Assistant Platform

An intelligent parenting support system that helps parents understand child behavior, health, and emotional development through an AI-powered chatbot.  
The platform includes secure authentication, onboarding questionnaires, AI model management, and document-based knowledge for personalized parenting insights.

---

## 🚀 Key Features

### 🔐 Authentication
- **Register:** Secure account creation for parents and admins.  
- **Email Verification with OTP:** Ensures valid and safe user access.  
- **Login with Email:** Traditional authentication with JWT/session handling.  
- **Login with Social Account:** One-click login using **Google** or **GitHub**.  
- **Forgot Password:** Password reset via email OTP for secure recovery.

---

### 🧭 Onboarding Flow

#### 👑 Admin
- **Add Questions:** Create onboarding questions of various types — `text`, `MCQ`, or `MSQ`.  
- **Update Questions:** Edit and modify existing onboarding forms.  
- **Delete Questions:** Remove outdated or irrelevant questions.

#### 🙋‍♀️ User
- **Submit Answers:** Respond to onboarding questions to personalize AI experience.  
- **Update Answers:** Modify answers when new questions are added or updated.

---

### 🤖 AI Model Management

#### 👑 Admin
- **Add Models:** Register or upload new AI/LLM models for child-behavioral processing.  
- **Set Active Model:** Define which model is currently in use for the system.  
- **Update Models:** Modify existing model metadata or configurations.  
- **Delete Models:** Remove outdated or unused model entries.

---

### 🧩 AI Knowledge Base and Query System

#### 👑 Admin
- **Upload Documents:** Add domain-specific parenting knowledge bases or datasets.  
- **Delete Documents:** Remove or replace old documents to keep the knowledge base updated.

#### 🙋‍♀️ User
- **Ask Queries:** Ask natural-language parenting questions directly to the chatbot.  
- **Delete Chat History:** Clear stored chat sessions for privacy and data control.

---

### ⚙️ Common Features (Admin & User)
- **Link/Unlink Social Accounts:** Manage connected OAuth providers (Google, GitHub).  
- **Update Password:** Securely update passwords through user settings.

---

### 👑 Admin Panel
- **Create New Admins:** Grant admin privileges to additional team members.  
- **Activate/Deactivate Users:** Manage user access and account activity.

---

### 🙋‍♀️ User Profile
- **View or Update Profile:** Edit personal details, parenting preferences, and demographics.  
- **Delete Profile:** Permanently remove personal data and account from the platform.

---

## 🧠 AI Features Overview
- **Custom Knowledge Base:** Upload tailored parenting resources for AI learning.  
- **Model Embeddings:** Integrates with models like `Gemini embedding-001` for high-quality document retrieval.  
- **Parent-Focused Q&A:** Handles complex parenting questions such as:
  - “Why does my 3-year-old throw tantrums?”
  - “How can I improve my child’s focus?”
  - “When should I be concerned about puberty?”
  - “How can I help my child with social anxiety?”
  - “What’s a healthy sleep schedule for a 10-year-old?”

---

## 🛠️ Tech Stack (Suggested Setup)

| Layer | Technologies |
|-------|---------------|
| **Backend** | FastAPI |
| **Database** | Supabase |
| **Authentication** | JWT, OAuth (Google, GitHub), Email OTP |
| **AI & Embeddings** | Gemini API, LangChain, LangGraph |

---

## 🧱 Database Entities (High-Level Overview)

- **User:** `id`, `name`, `email`, `password`, `role`, `is_verified`, `is_active`  
- **Question:** `id`, `type`, `text`, `options`, `created_by`  
- **Answer:** `id`, `user_id`, `question_id`, `response`  
- **Model:** `id`, `name`, `api_endpoint`, `is_active`  
- **Document:** `id`, `name`, `file_path`, `uploaded_by`  
- **Chat:** `id`, `user_id`, `query`, `response`, `timestamp`

---

## ⚙️ Setup & Installation

### 1️⃣ Clone Repository
```bash
git clone https://github.com/hacktheuni/nuture-bot.git
cd nuture-bot
