import React from 'react';

const LandingPage = ({ onAuthClick }) => {
  return (
    <div className="landing-page">
      <h2>Welcome to ServiceHub</h2>
      <p>Your one-stop solution for service management</p>
      <section>
        <h3>About Us</h3>
        <p>ServiceHub provides an efficient platform for managing and scheduling services.</p>
      </section>
      <section>
        <h3>Our Features</h3>
        <ul>
          <li>Easy service booking</li>
          <li>Real-time scheduling</li>
          <li>Service provider management</li>
          <li>Customer feedback system</li>
        </ul>
      </section>
      <button onClick={onAuthClick} className="cta-button">
        Get Started
      </button>
    </div>
  );
};

export default LandingPage;
