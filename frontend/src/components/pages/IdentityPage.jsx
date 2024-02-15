import React, { useContext, useEffect, useState } from "react";

import avatar from "../../assests/avatar.svg";
import closebtn from "../../assests/close-btn.svg";
import { MainContext } from "../../context/MainContext";
import copyIcon from "../../assests/copy.svg";

export default function IdentityPage() {
  const {
    toast,
    handlePage,
    peer_id,
    identity,
    handleRefresh,
    setToast,
    copytoClip,
  } = useContext(MainContext);

  const [image, setImage] = useState();
  const [uneditable, setunEditable] = useState(true);

  const [userData, setUserData] = useState({
    name: identity.name || "",
    email: identity.email || "",
    date_of_birth:
      new Date(identity.date_of_birth).toLocaleDateString("en-CA") || "",
    country_of_birth: identity.country_of_birth || "",
    city_of_birth: identity.city_of_birth || "",
    postal_address: identity.postal_address || "",
  });

  const [content, setContent] = useState({
    justify: "",
    close: false,
    sign: true,
  });
  const minDateObj = new Date();
  minDateObj.setFullYear(minDateObj.getFullYear() - 18);
  const minDateStr = minDateObj.toISOString().split("T")[0];

  // Calculate the maximum date (100 years ago)
  const maxDateObj = new Date();
  maxDateObj.setFullYear(maxDateObj.getFullYear() - 100);
  const maxDateStr = maxDateObj.toISOString().split("T")[0];
  const onChangeHandler = (e) => {
    let value = e.target.value;
    let name = e.target.name;
    console.log(value, maxDateStr);
    if (name === "date_of_birth") {
      if (value <= minDateStr && value >= maxDateStr) {
        setUserData({ ...userData, [name]: value });
      }
    } else {
      setUserData({ ...userData, [name]: value });
    }
  };
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      if (file.type === "image/jpeg" || file.name.endsWith(".jpg")) {
        setImage(URL.createObjectURL(file));
      } else {
        setImage(avatar);
      }
    }
  };

  // Set the minimum and maximum date states
  const peerIdLength = peer_id?.length;
  const handleSubmit = async (e) => {
    e.preventDefault();
    const form_data = new FormData(e.target);
    for (const [key, value] of Object.entries(userData)) {
      form_data.append(key, value);
    }
    await fetch("http://localhost:8000/identity/create", {
      method: "POST",
      body: form_data,
      mode: "cors",
    })
      .then((response) => {
        console.log(response);
        handleRefresh();
      })
      .catch((err) => console.log(err));
  };
  useEffect(() => {
    if (identity.name && identity.email) {
      setContent({
        justify: " justify-space",
        close: true,
        sign: false,
      });
    } else {
      setunEditable(false);
    }
  }, []);
  const checkPreview = () => {
    if (
      userData.name != "" &&
      userData.email != "" &&
      userData.date_of_birth != "Invalid Date"
    ) {
      setunEditable(!uneditable);
    } else {
      setToast("Please fill Required field");
    }
  };

  return (
    <div className="create">
      <div className={"create-head" + content.justify}>
        {content.sign ? (
          <span className="create-head-title">Create Identity</span>
        ) : (
          <span className="create-head-title">
            {!uneditable ? "Edit Identity" : "Identity"}
          </span>
        )}
        {content.close && (
          <img
            onClick={() => handlePage("home")}
            className="close-btn"
            src={closebtn}
          />
        )}
      </div>
      <form onSubmit={handleSubmit} className="create-body">
        <div className="create-body-avatar">
          {/* <input
            disabled={uneditable}
            onChange={handleFileChange}
            type="file"
            id="avatar"
          /> */}
          <label htmlFor="avatar">
            <img src={image ? image : avatar} />
            <span>{image ? "Change Photo" : "Add Photo"}</span>
          </label>
          {identity?.name && (
            <span
              onClick={() =>
                copytoClip(peer_id, "You Have Copied Node Identity")
              }
              className="identity-peerid"
            >
              {peer_id?.slice(0, 5)}...
              {peer_id?.slice(peerIdLength - 5, peerIdLength)}
              <img src={copyIcon} />
            </span>
          )}
        </div>
        <div className="create-body-form">
          <div className="create-body-form-input">
            <div
              className={
                toast !== "" && userData?.name === ""
                  ? "create-body-form-input-in invalid"
                  : "create-body-form-input-in"
              }
            >
              <label htmlFor="name">Full Name</label>
              <input
                required
                id="name"
                name="name"
                value={userData.name}
                disabled={uneditable}
                onChange={onChangeHandler}
                placeholder="Full Name"
                type="text"
              />
            </div>
            {/* <div className="create-body-form-input-in">
              <label htmlFor="phonenumber">Phone Number</label>
              <input

                id="phonenumber"
                value={userData.phone_number}
                disabled={uneditable}
                name="phone_number"
                onChange={onChangeHandler}
                placeholder="Phone Number"
                type="text"
              />
            </div> */}
            <div
              className={
                toast != "" && userData?.email === ""
                  ? "create-body-form-input-in invalid"
                  : "create-body-form-input-in"
              }
            >
              <label htmlFor="email">Email Address</label>
              <input
                required
                id="email"
                name="email"
                value={userData.email}
                disabled={uneditable}
                onChange={onChangeHandler}
                placeholder="Email Address"
                type="text"
              />
            </div>
            <div
              className={
                toast != "" && userData?.date_of_birth === "Invalid Date"
                  ? "create-body-form-input-in invalid"
                  : "create-body-form-input-in"
              }
            >
              <label htmlFor="date_of_birth">Date Of Birth</label>
              <input
                required
                id="date_of_birth"
                name="date_of_birth"
                value={userData.date_of_birth}
                min={maxDateStr}
                max={minDateStr}
                disabled={uneditable}
                onChange={onChangeHandler}
                placeholder=""
                type="date"
              />
            </div>
          </div>
          <div className="create-body-form-input">
            <div className="create-body-form-input-in">
              <label htmlFor="country_of_birth">Country Of Birth</label>
              <input
                required
                id="country_of_birth"
                name="country_of_birth"
                value={userData.country_of_birth}
                disabled={uneditable}
                onChange={onChangeHandler}
                placeholder="Country Of Birth"
                type="text"
              />
            </div>
            <div className="create-body-form-input-in">
              <label htmlFor="city_of_birth">City Of Birth</label>
              <input
                required
                id="city_of_birth"
                name="city_of_birth"
                value={userData.city_of_birth}
                disabled={uneditable}
                onChange={onChangeHandler}
                placeholder="Country Of Birth"
                type="text"
              />
            </div>
            <div className="create-body-form-input-in">
              <label htmlFor="postal_address">Postal Address</label>
              <input
                required
                id="postal_address"
                name="postal_address"
                value={userData.postal_address}
                disabled={uneditable}
                onChange={onChangeHandler}
                placeholder="Postal Address"
                type="text"
              />
            </div>
          </div>

          {/* <div
            className={
              toast != "" && userData?.email === ""
                ? "create-body-form-input-in invalid"
                : "create-body-form-input-in"
            }
          >
            <label htmlFor="email">Email Address</label>
            <input
              id="email"
              name="email"
              value={userData.email}
              disabled={uneditable}
              onChange={onChangeHandler}
              placeholder="Email Address"
              type="text"
            />
          </div> */}
          {/* <div
            className={
              toast != "" && userData?.date_of_birth === "Invalid Date"
                ? "create-body-form-input-in invalid"
                : "create-body-form-input-in"
            }
          >
            <label htmlFor="date_of_birth">Date Of Birth</label>
            <input
              id="date_of_birth"
              name="date_of_birth"
              value={userData.date_of_birth}
              disabled={uneditable}
              onChange={onChangeHandler}
              placeholder=""
              type="date"
            />
          </div> */}
        </div>
        {/* <div className="create-body-form-input">
          <div className="create-body-form-input-in">
            <label htmlFor="country_of_birth">Country Of Birth</label>
            <input
              id="country_of_birth"
              name="country_of_birth"
              value={userData.country_of_birth}
              disabled={uneditable}
              onChange={onChangeHandler}
              placeholder="Country Of Birth"
              type="text"
            />
          </div>
          <div className="create-body-form-input-in">
            <label htmlFor="city_of_birth">City Of Birth</label>
            <input
              id="city_of_birth"
              name="city_of_birth"
              value={userData.city_of_birth}
              disabled={uneditable}
              onChange={onChangeHandler}
              placeholder="Country Of Birth"
              type="text"
            />
          </div>
          <div className="create-body-form-input-in">
            <label htmlFor="postal_address">Postal Address</label>
            <input
              id="postal_address"
              name="postal_address"
              value={userData.postal_address}
              disabled={uneditable}
              onChange={onChangeHandler}
              placeholder="Postal Address"
              type="text"
            />
          </div>
          <div className="create-body-form-input-in">
            <label htmlFor="country_of_birth">Company</label>
            <input
              id="company"
              name="company"
              value={userData.company}
              disabled={uneditable}
              onChange={onChangeHandler}
              placeholder="Company"
              type="text"
            />
          </div>
        </div> */}

        {content.sign && (
          <div className="flex justify-space">
            <div onClick={checkPreview} className="create-body-btn">
              {uneditable ? "CANCEL" : "PREVIEW"}
            </div>
            {uneditable && (
              <input className="create-body-btn" type="submit" value="SIGN" />
            )}
          </div>
        )}
      </form>
    </div>
    //     {content.sign && (
    //       <div className="flex justify-space">
    //         <div onClick={checkPreview} className="create-body-btn">
    //           {uneditable ? "CANCEL" : "PREVIEW"}
    //         </div>
    //         {uneditable && (
    //           <input className="create-body-btn" type="submit" value="SIGN" />
    //         )}
    //       </div>
    //     )}
    //   </form>
    // </div>
  );
}
