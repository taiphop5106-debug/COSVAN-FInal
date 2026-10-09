-- เปิดใช้งาน uuid extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ==========================================
-- 1. สร้างตารางทั้งหมด (Tables)
-- ==========================================

-- ตารางผู้สอน
CREATE TABLE teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);

-- ตารางผู้เรียน (รหัสนักศึกษา 11 หลัก)
CREATE TABLE students (
    id VARCHAR(11) PRIMARY KEY CHECK (id ~ '^[0-9]{11}$'),
    title VARCHAR(50),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    section VARCHAR(50),
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT
);

-- ตารางการทำแบบทดสอบ (ทำได้ครั้งเดียวต่อประเภท pre/post)
CREATE TABLE attempts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(10) CHECK (kind IN ('pre', 'post')),
    score NUMERIC,
    answers JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, kind)
);

-- ตารางความก้าวหน้าการเรียน
CREATE TABLE progress (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INT,
    done BOOLEAN DEFAULT FALSE,
    UNIQUE(user_id, unit)
);

-- ตารางส่งงานปฏิบัติ AR
CREATE TABLE submissions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INT,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score NUMERIC,
    teacher_comment TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ตารางสื่อการเรียนที่ผู้สอนอัปโหลด
CREATE TABLE materials (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title TEXT,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================
-- 2. ฟังก์ชันความปลอดภัยและนโยบาย RLS
-- ==========================================

-- ฟังก์ชันตรวจสอบว่าเป็นผู้สอนหรือไม่ (Security Definer)
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS boolean AS $$
    SELECT EXISTS (SELECT 1 FROM public.teachers WHERE user_id = auth.uid());
$$ LANGUAGE sql SECURITY DEFINER SET search_path = public;

-- เปิด RLS ทุกตาราง
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE materials ENABLE ROW LEVEL SECURITY;

-- ถอดสิทธิ์พื้นฐานและให้สิทธิ์เฉพาะ Authenticated เท่าที่จำเป็น
REVOKE ALL ON teachers FROM anon, authenticated;
REVOKE ALL ON students FROM anon, authenticated;
REVOKE ALL ON attempts FROM anon, authenticated;
REVOKE ALL ON progress FROM anon, authenticated;
REVOKE ALL ON submissions FROM anon, authenticated;
REVOKE ALL ON materials FROM anon, authenticated;

GRANT SELECT ON teachers TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON students TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON attempts TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON progress TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON submissions TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON materials TO authenticated;

-- นโยบายตาราง students
CREATE POLICY "Teacher read all students" ON students FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read own student record" ON students FOR SELECT TO authenticated USING (user_id = auth.uid());
-- ผู้เรียนแก้ได้เฉพาะของตนเอง (การป้องกันไม่ให้แก้คอลัมน์อื่นจัดการที่ Frontend และระดับสิทธิ์พื้นฐาน)
CREATE POLICY "Student update own record" ON students FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- นโยบายตาราง attempts
CREATE POLICY "Teacher read attempts" ON attempts FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read own attempts" ON attempts FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own attempts" ON attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() AND NOT is_teacher());

-- นโยบายตาราง progress
CREATE POLICY "Teacher read progress" ON progress FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Student read own progress" ON progress FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own progress" ON progress FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() AND NOT is_teacher());
CREATE POLICY "Student update own progress" ON progress FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid() AND NOT is_teacher());

-- นโยบายตาราง submissions
CREATE POLICY "Teacher read all submissions" ON submissions FOR SELECT TO authenticated USING (is_teacher());
CREATE POLICY "Teacher update submissions" ON submissions FOR UPDATE TO authenticated USING (is_teacher());
CREATE POLICY "Student read own submissions" ON submissions FOR SELECT TO authenticated USING (user_id = auth.uid());
CREATE POLICY "Student insert own submissions" ON submissions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() AND NOT is_teacher());
CREATE POLICY "Student update own submissions" ON submissions FOR UPDATE TO authenticated USING (user_id = auth.uid() AND NOT is_teacher());

-- Trigger ป้องกันผู้เรียนแก้คะแนนหรือข้อเสนอแนะของผู้สอนใน submissions
CREATE OR REPLACE FUNCTION protect_submission_grading() RETURNS trigger AS $$
BEGIN
    IF NOT is_teacher() THEN
        IF NEW.score IS DISTINCT FROM OLD.score OR NEW.teacher_comment IS DISTINCT FROM OLD.teacher_comment THEN
            RAISE EXCEPTION 'ผู้เรียนไม่สามารถแก้ไขคะแนนหรือข้อเสนอแนะได้';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER trigger_protect_submission_grading
BEFORE UPDATE ON submissions
FOR EACH ROW EXECUTE FUNCTION protect_submission_grading();

-- นโยบายตาราง materials
CREATE POLICY "Anyone authenticated read materials" ON materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Teacher manage materials" ON materials FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());

-- ==========================================
-- 3. ระบบผูกบัญชีอัตโนมัติเมื่อสมัคร (Trigger)
-- ==========================================
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger AS $$
DECLARE
    student_id_prefix VARCHAR;
BEGIN
    -- ถ้าอีเมลขึ้นต้นด้วยตัวเลข 11 หลัก ให้ประมวลผลเป็นผู้เรียน
    IF NEW.email ~ '^[0-9]{11}@' THEN
        student_id_prefix := SUBSTRING(NEW.email FROM '^([0-9]{11})@');
        
        -- ตรวจสอบว่ามีรายชื่อในระบบและยังไม่มีใครใช้
        IF NOT EXISTS (SELECT 1 FROM public.students WHERE id = student_id_prefix AND user_id IS NULL) THEN
            RAISE EXCEPTION 'ไม่พบรหัสนักศึกษานี้ในรายชื่อผู้มีสิทธิ์เรียน หรือบัญชีถูกผูกไปแล้ว';
        END IF;
        
        -- ผูก user_id ของ Auth กับตาราง students
        UPDATE public.students SET user_id = NEW.id WHERE id = student_id_prefix;
    END IF;
    -- หากไม่ใช่ 11 หลัก ให้ผ่านไป (สำหรับสร้างบัญชีผู้สอนทีหลัง)
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==========================================
-- 4. มุมมองสำหรับผู้สอน (Security Invoker)
-- ==========================================
CREATE OR REPLACE VIEW results WITH (security_invoker = true) AS
SELECT s.id, s.title, s.first_name, s.last_name, s.section, s.photo_path,
       MAX(CASE WHEN a.kind = 'pre' THEN a.score END) as pre_score,
       MAX(CASE WHEN a.kind = 'post' THEN a.score END) as post_score
FROM students s
LEFT JOIN attempts a ON s.user_id = a.user_id
GROUP BY s.id, s.title, s.first_name, s.last_name, s.section, s.photo_path;

-- ==========================================
-- 5. ระบบ Storage (สร้างและตั้งกฎ)
-- ==========================================
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types) 
VALUES 
  ('photos', 'photos', false, 2097152, ARRAY['image/jpeg', 'image/png']),
  ('submissions', 'submissions', false, 20971520, ARRAY['image/jpeg', 'image/png', 'application/pdf', 'video/mp4']),
  ('materials', 'materials', false, 52428800, ARRAY['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/pdf'])
ON CONFLICT (id) DO UPDATE SET 
  file_size_limit = EXCLUDED.file_size_limit,
  allowed_mime_types = EXCLUDED.allowed_mime_types,
  public = false;

-- กฎสำหรับรูปโปรไฟล์ (photos)
CREATE POLICY "Students upload own photo" ON storage.objects FOR INSERT TO authenticated
WITH CHECK ( bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text );

CREATE POLICY "Students update own photo" ON storage.objects FOR UPDATE TO authenticated
USING ( bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text );

CREATE POLICY "Users read photos" ON storage.objects FOR SELECT TO authenticated USING ( bucket_id = 'photos' );

CREATE POLICY "Students delete own photo" ON storage.objects FOR DELETE TO authenticated USING ( bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text );

-- กฎสำหรับงานส่ง (submissions)
CREATE POLICY "Students upload own submissions" ON storage.objects FOR INSERT TO authenticated
WITH CHECK ( bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text );

CREATE POLICY "Teacher read all submissions" ON storage.objects FOR SELECT TO authenticated
USING ( bucket_id = 'submissions' AND (is_teacher() OR (storage.foldername(name))[1] = auth.uid()::text) );

CREATE POLICY "Students delete own submissions" ON storage.objects FOR DELETE TO authenticated USING ( bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text );

-- กฎสำหรับสื่อการเรียน (materials)
CREATE POLICY "Teacher manage materials" ON storage.objects FOR ALL TO authenticated 
USING ( bucket_id = 'materials' AND is_teacher() ) WITH CHECK ( bucket_id = 'materials' AND is_teacher() );

CREATE POLICY "All authenticated read materials" ON storage.objects FOR SELECT TO authenticated USING ( bucket_id = 'materials' );

-- ==========================================
-- 6. ข้อมูลจำลอง (Mock Data) 6 แถวแรก
-- ==========================================
-- วิธีนำเข้ารายชื่อจริง: ใช้ Table Editor ใน Supabase Import CSV เข้าตาราง students
INSERT INTO students (id, title, first_name, last_name, section) VALUES
('11000000001', 'นาย', 'สมชาย', 'เรียนดี', '4/1'),
('11000000002', 'นางสาว', 'สมหญิง', 'ขยันยิ่ง', '4/1'),
('11000000003', 'นาย', 'กิตติ', 'มานะ', '4/2'),
('11000000004', 'นางสาว', 'วิภา', 'ใจใส', '4/2'),
('11000000005', 'นาย', 'ธนพล', 'อดทน', '4/3'),
('11000000006', 'นางสาว', 'สุชาดา', 'ร่าเริง', '4/3')
ON CONFLICT DO NOTHING;

-- ==========================================
-- 7. คำสั่งแต่งตั้งผู้สอน (ให้ผู้ดูแลระบบรันหลังสมัครอีเมลเสร็จ)
-- ==========================================
/*
DO $$
DECLARE target_uid UUID;
BEGIN
  -- เปลี่ยนอีเมลตรงนี้เป็นอีเมลของผู้สอนที่สมัครสมาชิกไว้แล้ว
  SELECT id INTO target_uid FROM auth.users WHERE email = 'teacher@school.ac.th';
  
  IF target_uid IS NOT NULL THEN
     INSERT INTO teachers (user_id) VALUES (target_uid) ON CONFLICT DO NOTHING;
  END IF;
END $$;
*/
