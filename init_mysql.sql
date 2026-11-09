-- Sample data for the Secure MCP Scanner demo (MySQL).
-- Contains intentionally realistic PII so the scanner has something to find.

CREATE DATABASE IF NOT EXISTS sample_db;
USE sample_db;

CREATE TABLE IF NOT EXISTS customers (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100),
  phone VARCHAR(20),
  pan_number VARCHAR(10),
  address TEXT,
  metadata JSON
);

INSERT INTO customers (name, email, phone, pan_number, address, metadata) VALUES
('Rahul Sharma', 'rahul.sharma@example.com', '+919876543210', 'ABCDE1234F', '123 MG Road, Bangalore 560001', '{"source": "web", "tier": "gold", "kyc": {"aadhaar": "4589 6231 7452", "email": "rahul.kyc@example.com"}}'),
('Priya Patel', 'priya.patel@gmail.com', '+919876543211', 'FGHIJ5678K', '456 Park Street, Mumbai 400001', '{"source": "mobile", "tier": "silver"}'),
('Arjun Mehta', 'arjun.mehta@yahoo.com', '+919812345678', 'KLMNO2345P', '789 Brigade Road, Bengaluru 560025', '{"source": "web", "tier": "gold"}'),
('Sneha Iyer', 'sneha.iyer@outlook.com', '+919899001122', 'PQRST7890Q', '321 Anna Salai, Chennai 600002', '{"source": "branch", "tier": "bronze"}'),
('Vikram Singh', 'vikram.singh@example.com', '+919834512678', 'UVWXY3456R', '654 Connaught Place, New Delhi 110001, Aadhaar: 4589 6231 7452', '{"source": "web", "tier": "gold", "kyc": {"aadhaar": "7412 8563 9074", "email": "vikram.kyc@example.com"}}'),
('Ananya Reddy', 'ananya.reddy@gmail.com', '+919865432198', 'ZABCD4567S', '987 Road No. 12, Banjara Hills, Hyderabad 500034', '{"source": "mobile", "tier": "silver"}'),
('Karan Malhotra', 'karan.malhotra@example.com', '+919876123450', 'CDEFG5678T', '222 Marine Drive, Mumbai 400020', '{"source": "web", "tier": "bronze"}'),
('Deepika Nair', 'deepika.nair@yahoo.com', '+919845098450', 'HIJKL6789U', '55 MG Road, Kochi 682016, Aadhaar: 9034 1276 5842', '{"source": "branch", "tier": "gold", "kyc": {"aadhaar": "8203 9174 6553", "email": "deepika.kyc@example.com"}}');

-- A view, so the scanner has a non-table relation to walk.
CREATE OR REPLACE VIEW customer_emails AS
SELECT name, email, phone FROM customers WHERE email IS NOT NULL;

-- Patient records, so the scanner has protected health information to find.
CREATE TABLE IF NOT EXISTS patient_records (
  id INT AUTO_INCREMENT PRIMARY KEY,
  mrn VARCHAR(40),
  patient_name VARCHAR(100),
  dob VARCHAR(20),
  phone VARCHAR(20),
  email VARCHAR(100),
  diagnosis TEXT,
  medication TEXT,
  provider_name VARCHAR(100),
  provider_license VARCHAR(40),
  health_plan_id VARCHAR(40),
  device_serial VARCHAR(40),
  notes TEXT
);

INSERT INTO patient_records (mrn, patient_name, dob, phone, email, diagnosis, medication, provider_name, provider_license, health_plan_id, device_serial, notes) VALUES
('MRN: 4471-B', 'Ananya Sharma', '1990-05-12', '+919876543210', 'ananya.sharma@example.com', 'Type 2 Diabetes Mellitus', 'Metformin 500mg', 'Dr. Rajesh Menon', 'MCI-2019-114322', 'PMJAY-HI-2023-889120', 'SN: DEX-004512', 'Type 2 Diabetes Mellitus; blood glucose monitored monthly.'),
('MRN: 2298-C', 'Vikram Deshpande', '1978-11-30', '9822011234', 'vikram.d@example.com', 'Hypertension stage 2', 'Amlodipine 10mg', 'Dr. Meera Iyer', 'MCI-2015-887401', 'ESIC-22334455', 'SN: OMR-771200', 'Hypertension; advised a low-sodium diet.'),
('MRN: 8831-A', 'Fatima Sheikh', '1995-03-08', '+919004011223', 'fatima.sheikh@example.com', 'Anaemia', 'Ferrous sulphate 325mg', 'Dr. Arjun Kapoor', 'MCI-2021-334512', 'CGHS-55667788', 'SN: CGM-118834', 'Anaemia; haemoglobin under review.'),
('MRN: 5567-D', 'Arjun Nair', '1965-07-19', '9819922334', 'arjun.nair@example.com', 'Type 2 Diabetes Mellitus with neuropathy', 'Insulin glargine 100IU', 'Dr. Sunita Rao', 'MCI-2012-220987', 'PMJAY-HI-2021-334567', 'SN: INS-991233', 'Type 2 Diabetes Mellitus; insulin titration ongoing.'),
('MRN: 1024-F', 'Kavita Reddy', '1988-01-25', '9701122334', 'kavita.reddy@example.com', 'Migraine', 'Sumatriptan 50mg', 'Dr. Ishan Bose', 'MCI-2018-660412', 'TMC-77889900', 'SN: NEU-223344', 'Migraine episodes twice weekly.'),
('MRN: 7733-B', 'Harpreet Singh', '1992-09-14', '9988776655', 'harpreet.singh@example.com', 'Asthma', 'Salbutamol inhaler', 'Dr. Nisha Kulkarni', 'MCI-2020-445566', 'ESIC-11223344', 'SN: SPI-556677', 'Asthma; inhaler used before exercise.'),
('MRN: 3390-C', 'Deepa Krishnan', '2001-04-02', '9845012345', 'deepa.k@example.com', 'Anxiety disorder', 'Sertraline 50mg', 'Dr. Vivek Joshi', 'MCI-2017-998877', 'CGHS-44556677', 'SN: ECG-334455', 'Anxiety disorder; fortnightly review.'),
('MRN: 6612-E', 'Mohit Bansal', '1974-12-21', '9876543210', 'mohit.bansal@example.com', 'Hypothyroidism', 'Levothyroxine 75mcg', 'Dr. Ananya Verma', 'MCI-2014-112233', 'PMJAY-HI-2019-990011', 'SN: PUL-667788', 'Hypothyroidism; TSH stable.');

-- Card payments, so the scanner has cardholder data to find.
CREATE TABLE IF NOT EXISTS payments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  payment_id VARCHAR(20),
  cardholder_name VARCHAR(100),
  card_number VARCHAR(30),
  expiry VARCHAR(10),
  cvv VARCHAR(10),
  amount DECIMAL(12, 2),
  billing_postcode VARCHAR(10),
  customer_email VARCHAR(100)
);

INSERT INTO payments (payment_id, cardholder_name, card_number, expiry, cvv, amount, billing_postcode, customer_email) VALUES
('PAY-1001', 'Ananya Sharma', '4111111111111111', '12/28', '123', 1299.50, '560001', 'ananya.sharma@example.com'),
('PAY-1002', 'Vikram Deshpande', '5500 0055 5555 5559', '04/27', '456', 249.00, '400001', 'vikram.d@example.com'),
('PAY-1003', 'Fatima Sheikh', '378282246310005', '11/26', '1234', 89.99, '400050', 'fatima.sheikh@example.com'),
('PAY-1004', 'Arjun Nair', '4012 8888 8888 1881', '08/29', '737', 5400.00, '682001', 'arjun.nair@example.com'),
('PAY-1005', 'Kavita Reddy', '5105 1051 0510 5100', '02/27', '991', 1999.99, '500002', 'kavita.reddy@example.com'),
('PAY-1006', 'Harpreet Singh', '2223 0031 2200 3222', '06/28', '214', 349.50, '110001', 'harpreet.singh@example.com'),
('PAY-1007', 'Deepa Krishnan', '3714 4963 5398 431', '09/27', '3120', 75.25, '700001', 'deepa.k@example.com'),
('PAY-1008', 'Mohit Bansal', '4222 2222 2222 2', '03/28', '556', 12000.00, '110001', 'mohit.bansal@example.com');

