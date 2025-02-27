export async function checkURLWithDB(url) {
  console.log(`Checking ${url} with DB`);
  try {
    const response = await fetch(`http://52.229.164.233:4000/check?url=${url}`);
    const data = await response.json();
    if (!data.stored) {
      console.log('Site not found in DB');
      return false;
    } else {
      console.log('Site is whitelisted in DB');
      return true;
    }
  } catch (err) {
    console.error('Error checking domain in DB:', err);
    return null;
  }
}

export async function addURLToDB(url) {
  console.log(`Adding ${url} to DB`);
  try {
    const insertResponse = await fetch('http://52.229.164.233:4000/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });
    const insertData = await insertResponse.json();
    if (insertData.success) {
      console.log(`Domain ${url} added to DB`);
    } else {
      console.log('Failed to add domain to DB');
    }
  } catch (err) {
    console.error('Error adding domain to DB:', err);
  }
}