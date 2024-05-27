import React from "react";

interface PasswordCardProps {
  item: {
    id: number;
    title?: string;
    user_name?: string;
    user_password?: string;
  };
  onCopy: (id: number) => void;
  onDelete: (id: number) => void;
}

const PasswordCard: React.FC<PasswordCardProps> = ({
  item,
  onCopy,
  onDelete,
}) => (
  <div
    className="card darkColor mb-6 p-6 md:mb-3 md:p-3"
    style={{ width: "fit-content" }}
  >
    <div className="card-body">
      <h5 className="card-title darkGreen text-2xl md:text-lg">{item.title}</h5>
      <p className="card-text oliveGreen text-lg md:text-base">
        {item.user_name}
      </p>
      <div className="mt-4 flex items-center justify-center md:mt-2">
        <span className="password-link text-xl md:text-base">●●●●●●●●</span>
        <button
          className="btn yellow darkColor Copy ms-3 text-lg md:text-base"
          onClick={() => onCopy(item.id)}
        >
          Copy
        </button>
      </div>
      <div className="mt-6 flex justify-center md:mt-3">
        <a
          href={`/${item.id}`}
          className="btn yellow darkColor update text-lg md:text-base"
        >
          Update
        </a>
      </div>
      <div className="mt-6 flex justify-center md:mt-3">
        <button
          className="btn yellow darkColor delete text-lg md:text-base"
          onClick={() => onDelete(item.id)}
        >
          Delete
        </button>
      </div>
    </div>
  </div>
);

export default PasswordCard;
