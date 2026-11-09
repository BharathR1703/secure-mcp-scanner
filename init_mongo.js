// Sample data for the Secure MCP Scanner demo (MongoDB).
// Documents are nested on purpose, so the scanner has to flatten them.

const sample = db.getSiblingDB("sample_db");

sample.customers.insertMany([
  {
    name: "Rahul Sharma",
    email: "rahul.sharma@example.com",
    phone: "+919876543210",
    pan_number: "ABCDE1234F",
    address: { line1: "123 MG Road", city: "Bangalore", pincode: "560001" },
    aadhaar: "4589 6231 7452",
    metadata: {
      source: "web",
      tier: "gold",
      tags: ["kyc", "vip"],
      kyc: { aadhaar: "9034 1276 5842", email: "rahul.kyc@example.com" }
    }
  },
  {
    name: "Priya Patel",
    email: "priya.patel@gmail.com",
    phone: "+919876543211",
    pan_number: "FGHIJ5678K",
    address: { line1: "456 Park Street", city: "Mumbai", pincode: "400001" },
    metadata: { source: "mobile", tier: "silver", tags: ["kyc"] }
  },
  {
    name: "Arjun Mehta",
    email: "arjun.mehta@yahoo.com",
    phone: "+919812345678",
    pan_number: "KLMNO2345P",
    address: { line1: "789 Brigade Road", city: "Bengaluru", pincode: "560025" },
    aadhaar: "7412 8563 9074",
    metadata: {
      source: "web",
      tier: "gold",
      tags: ["vip"],
      kyc: { aadhaar: "8203 9174 6553", email: "arjun.kyc@example.com" }
    }
  },
  {
    name: "Sneha Iyer",
    email: "sneha.iyer@outlook.com",
    phone: "+919899001122",
    pan_number: "PQRST7890Q",
    address: { line1: "321 Anna Salai", city: "Chennai", pincode: "600002" },
    metadata: { source: "branch", tier: "bronze", tags: [] }
  }
]);

// A second collection holding contact details with nested structure.
sample.contacts.insertMany([
  {
    full_name: "Vikram Singh",
    contact: {
      email: "vikram.singh@example.com",
      phone: "+919834512678",
      emergency: { name: "Meera Krishnan", phone: "+919640123456" }
    },
    pan_number: "UVWXY3456R",
    address: { line1: "654 Connaught Place", city: "New Delhi", pincode: "110001" }
  },
  {
    full_name: "Ananya Reddy",
    contact: {
      email: "ananya.reddy@gmail.com",
      phone: "+919865432198",
      emergency: { name: "Rahul Sharma", phone: "+919876543210" }
    },
    pan_number: "ZABCD4567S",
    address: { line1: "987 Road No. 12", city: "Hyderabad", pincode: "500034" }
  }
]);

// Patient records, so the scanner has protected health information to find.
// The documents are nested on purpose, so the flattener has to walk them
// and still recognise the fields.
sample.patients.insertMany([
  {
    mrn: "MRN: 4471-B",
    name: "Ananya Sharma",
    dob: "1990-05-12",
    contact: { phone: "+919876543210", email: "ananya.sharma@example.com" },
    clinical: {
      diagnosis: "Type 2 Diabetes Mellitus",
      medication: "Metformin 500mg",
      provider: { name: "Dr. Rajesh Menon", license: "MCI-2019-114322" }
    },
    coverage: { health_plan_id: "PMJAY-HI-2023-889120" },
    device: { serial: "SN: DEX-004512" },
    notes: "Type 2 Diabetes Mellitus; blood glucose monitored monthly."
  },
  {
    mrn: "MRN: 2298-C",
    name: "Vikram Deshpande",
    dob: "1978-11-30",
    contact: { phone: "9822011234", email: "vikram.d@example.com" },
    clinical: {
      diagnosis: "Hypertension stage 2",
      medication: "Amlodipine 10mg",
      provider: { name: "Dr. Meera Iyer", license: "MCI-2015-887401" }
    },
    coverage: { health_plan_id: "ESIC-22334455" },
    device: { serial: "SN: OMR-771200" },
    notes: "Hypertension; advised a low-sodium diet."
  },
  {
    mrn: "MRN: 8831-A",
    name: "Fatima Sheikh",
    dob: "1995-03-08",
    contact: { phone: "+919004011223", email: "fatima.sheikh@example.com" },
    clinical: {
      diagnosis: "Anaemia",
      medication: "Ferrous sulphate 325mg",
      provider: { name: "Dr. Arjun Kapoor", license: "MCI-2021-334512" }
    },
    coverage: { health_plan_id: "CGHS-55667788" },
    device: { serial: "SN: CGM-118834" },
    notes: "Anaemia; haemoglobin under review."
  },
  {
    mrn: "MRN: 5567-D",
    name: "Arjun Nair",
    dob: "1965-07-19",
    contact: { phone: "9819922334", email: "arjun.nair@example.com" },
    clinical: {
      diagnosis: "Type 2 Diabetes Mellitus with neuropathy",
      medication: "Insulin glargine 100IU",
      provider: { name: "Dr. Sunita Rao", license: "MCI-2012-220987" }
    },
    coverage: { health_plan_id: "PMJAY-HI-2021-334567" },
    device: { serial: "SN: INS-991233" },
    notes: "Type 2 Diabetes Mellitus; insulin titration ongoing."
  },
  {
    mrn: "MRN: 1024-F",
    name: "Kavita Reddy",
    dob: "1988-01-25",
    contact: { phone: "9701122334", email: "kavita.reddy@example.com" },
    clinical: {
      diagnosis: "Migraine",
      medication: "Sumatriptan 50mg",
      provider: { name: "Dr. Ishan Bose", license: "MCI-2018-660412" }
    },
    coverage: { health_plan_id: "TMC-77889900" },
    device: { serial: "SN: NEU-223344" },
    notes: "Migraine episodes twice weekly."
  },
  {
    mrn: "MRN: 7733-B",
    name: "Harpreet Singh",
    dob: "1992-09-14",
    contact: { phone: "9988776655", email: "harpreet.singh@example.com" },
    clinical: {
      diagnosis: "Asthma",
      medication: "Salbutamol inhaler",
      provider: { name: "Dr. Nisha Kulkarni", license: "MCI-2020-445566" }
    },
    coverage: { health_plan_id: "ESIC-11223344" },
    device: { serial: "SN: SPI-556677" },
    notes: "Asthma; inhaler used before exercise."
  },
  {
    mrn: "MRN: 3390-C",
    name: "Deepa Krishnan",
    dob: "2001-04-02",
    contact: { phone: "9845012345", email: "deepa.k@example.com" },
    clinical: {
      diagnosis: "Anxiety disorder",
      medication: "Sertraline 50mg",
      provider: { name: "Dr. Vivek Joshi", license: "MCI-2017-998877" }
    },
    coverage: { health_plan_id: "CGHS-44556677" },
    device: { serial: "SN: ECG-334455" },
    notes: "Anxiety disorder; fortnightly review."
  },
  {
    mrn: "MRN: 6612-E",
    name: "Mohit Bansal",
    dob: "1974-12-21",
    contact: { phone: "9876543210", email: "mohit.bansal@example.com" },
    clinical: {
      diagnosis: "Hypothyroidism",
      medication: "Levothyroxine 75mcg",
      provider: { name: "Dr. Ananya Verma", license: "MCI-2014-112233" }
    },
    coverage: { health_plan_id: "PMJAY-HI-2019-990011" },
    device: { serial: "SN: PUL-667788" },
    notes: "Hypothyroidism; TSH stable."
  }
]);

// Card payments, so the scanner has cardholder data to find.
sample.payments.insertMany([
  {
    payment_id: "PAY-1001",
    card: { name: "Ananya Sharma", number: "4111111111111111", expiry: "12/28", cvv: "123" },
    amount: 1299.50,
    billing: { postcode: "560001" },
    contact: { email: "ananya.sharma@example.com" }
  },
  {
    payment_id: "PAY-1002",
    card: { name: "Vikram Deshpande", number: "5500 0055 5555 5559", expiry: "04/27", cvv: "456" },
    amount: 249.0,
    billing: { postcode: "400001" },
    contact: { email: "vikram.d@example.com" }
  },
  {
    payment_id: "PAY-1003",
    card: { name: "Fatima Sheikh", number: "378282246310005", expiry: "11/26", cvv: "1234" },
    amount: 89.99,
    billing: { postcode: "400050" },
    contact: { email: "fatima.sheikh@example.com" }
  },
  {
    payment_id: "PAY-1004",
    card: { name: "Arjun Nair", number: "4012 8888 8888 1881", expiry: "08/29", cvv: "737" },
    amount: 5400.0,
    billing: { postcode: "682001" },
    contact: { email: "arjun.nair@example.com" }
  },
  {
    payment_id: "PAY-1005",
    card: { name: "Kavita Reddy", number: "5105 1051 0510 5100", expiry: "02/27", cvv: "991" },
    amount: 1999.99,
    billing: { postcode: "500002" },
    contact: { email: "kavita.reddy@example.com" }
  },
  {
    payment_id: "PAY-1006",
    card: { name: "Harpreet Singh", number: "2223 0031 2200 3222", expiry: "06/28", cvv: "214" },
    amount: 349.5,
    billing: { postcode: "110001" },
    contact: { email: "harpreet.singh@example.com" }
  },
  {
    payment_id: "PAY-1007",
    card: { name: "Deepa Krishnan", number: "3714 4963 5398 431", expiry: "09/27", cvv: "3120" },
    amount: 75.25,
    billing: { postcode: "700001" },
    contact: { email: "deepa.k@example.com" }
  },
  {
    payment_id: "PAY-1008",
    card: { name: "Mohit Bansal", number: "4222 2222 2222 2", expiry: "03/28", cvv: "556" },
    amount: 12000.0,
    billing: { postcode: "110001" },
    contact: { email: "mohit.bansal@example.com" }
  }
]);
