import React from 'react';

const LandingPage = ({ onAuthClick }) => {
  return (
    <div className="landing-page">
      <header>
        <h1>Welcome to ServiceHub</h1>
        <p>Your one-stop solution for service management</p>
      </header>
      <main>
        <section>
          <h2>About Us</h2>
          <p>ServiceHub provides an efficient platform for managing and scheduling services.</p>
        </section>
        <section>
          <h2>Our Features</h2>
          <ul>
            <li>Easy service booking</li>
            <li>Real-time scheduling</li>
            <li>Service provider management</li>
            <li>Customer feedback system</li>
          </ul>
        </section>
        <button onClick={onAuthClick} className="cta-button">
          Register / Login
        </button>
      </main>
      <footer>
        <p>&copy; 2024 ServiceHub. All rights reserved.</p>
      </footer>
    </div>
  );
};

export default LandingPage;
